"""Bounded, opt-in runtime capture for Python tools.

The implementation deliberately refuses to fall back to an unsandboxed run.
On Linux it uses bubblewrap for namespace isolation and strace for syscall
capture. On other platforms it returns a structured ``sandbox_unavailable``
profile that callers can report rather than treating as a pass.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Iterable, Sequence

from pydantic import BaseModel, Field


class RuntimeFileAccess(BaseModel):
    path: str
    modes: list[str] = Field(default_factory=list)


class RuntimeNetworkAccess(BaseModel):
    operation: str
    address: str
    port: int | None = None
    family: str | None = None


class RuntimeProcess(BaseModel):
    executable: str
    arguments: list[str] = Field(default_factory=list)


class RuntimeProfile(BaseModel):
    schema_version: str = "1.0"
    target: str
    status: str = "not_run"
    sandbox: str = "bubblewrap+strace"
    files_touched: list[RuntimeFileAccess] = Field(default_factory=list)
    network_connections: list[RuntimeNetworkAccess] = Field(default_factory=list)
    subprocesses: list[RuntimeProcess] = Field(default_factory=list)
    system_resources: list[str] = Field(default_factory=list)
    exit_code: int | None = None
    timed_out: bool = False
    duration_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""
    error: str | None = None


class RuntimeCapture:
    def __init__(self, timeout_seconds: float = 10.0, max_output_chars: int = 4000):
        self.timeout_seconds = timeout_seconds
        self.max_output_chars = max_output_chars

    def capture(
        self,
        repo_path: Path,
        *,
        command: Sequence[str] | None = None,
        input_payload: dict | None = None,
    ) -> RuntimeProfile:
        target = Path(repo_path).resolve()
        root = target.parent if target.is_file() else target
        if not target.exists():
            return RuntimeProfile(target=str(target), status="invalid_target", error="Target does not exist")
        if os.name != "posix" or not sys.platform.startswith("linux"):
            return RuntimeProfile(target=str(target), status="sandbox_unavailable", error="Runtime verification requires Linux")

        bwrap = shutil.which("bwrap")
        strace = shutil.which("strace")
        if not bwrap or not strace:
            missing = ", ".join(name for name, value in (("bwrap", bwrap), ("strace", strace)) if not value)
            return RuntimeProfile(target=str(target), status="sandbox_unavailable", error=f"Missing required tool(s): {missing}")

        try:
            inner_command = list(command or self._default_command(target, root))
        except ValueError as exc:
            return RuntimeProfile(target=str(target), status="could_not_execute", error=str(exc))

        with tempfile.TemporaryDirectory(prefix="skillguard_trace_") as trace_dir, tempfile.TemporaryDirectory(prefix="skillguard_workspace_") as workspace_dir:
            trace_prefix = str(Path(trace_dir) / "trace")
            sandbox_root = Path(workspace_dir) / "repo"
            try:
                shutil.copytree(
                    root,
                    sandbox_root,
                    symlinks=True,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules"),
                )
            except OSError as exc:
                return RuntimeProfile(target=str(target), status="could_not_execute", error=f"Could not stage sandbox workspace: {exc}")

            # Ensure workspace directory permissions for dropped privileges (uid 65534)
            for dirpath, _, _ in os.walk(workspace_dir):
                try:
                    os.chmod(dirpath, 0o777)
                except OSError:
                    pass

            # Pre-execution: sandboxed dependency installation
            self._install_dependencies(bwrap, sandbox_root)

            sandbox_command = self._sandbox_command(bwrap, sandbox_root, inner_command)
            full_command = [strace, "-ff", "-o", trace_prefix, "-s", "256", "-e", "trace=file,network,process", *sandbox_command]
            if input_payload is not None:
                payload = json.dumps(input_payload) + "\n"
            else:
                payload = (
                    json.dumps({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "skillguard", "version": "0.1.0"}
                        }
                    }) + "\n"
                    + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}) + "\n"
                    + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}) + "\n"
                )
            started = time.monotonic()
            try:
                process = subprocess.Popen(
                    full_command,
                    cwd=str(sandbox_root),
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    stdout, stderr = process.communicate(input=payload, timeout=self.timeout_seconds)
                    timed_out = False
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                    timed_out = True
            except OSError as exc:
                return RuntimeProfile(target=str(target), status="could_not_execute", error=str(exc))

            ignored_processes = {str(Path(bwrap).resolve())}
            if inner_command:
                ignored_processes.add(str(Path(inner_command[0]).resolve()))
            profile = self._parse_traces(target, trace_dir, ignored_processes=ignored_processes)
            profile.exit_code = process.returncode
            profile.timed_out = timed_out
            profile.duration_seconds = round(time.monotonic() - started, 3)
            profile.stdout = stdout[-self.max_output_chars:]
            profile.stderr = stderr[-self.max_output_chars:]

            stderr_lower = stderr.lower()
            if "modulenotfounderror:" in stderr_lower or "importerror:" in stderr_lower or "no module named" in stderr_lower:
                profile.status = "dependency_missing"
                match = re.search(r"(?:No module named|No module named ')([^'\s\n]+)", stderr)
                missing = match.group(1) if match else "unknown"
                profile.error = f"Missing dependency: {missing}"
            elif timed_out:
                if ('"jsonrpc"' in stdout and ('"result"' in stdout or '"capabilities"' in stdout)) or ('"tools"' in stdout):
                    profile.status = "completed"
                    profile.error = None
                elif not stdout.strip() and not stderr.strip():
                    profile.status = "awaiting_handshake"
                    profile.error = "Process awaited input or interactive client connection"
                else:
                    profile.status = "timeout"
                    profile.error = f"Tool exceeded {self.timeout_seconds:g}s timeout"
            elif process.returncode != 0:
                if any(phrase in stderr_lower for phrase in ("eof", "broken pipe", "unexpected end of file", "jsondecodeerror")):
                    profile.status = "awaiting_handshake"
                    profile.error = "Server terminated awaiting full MCP interaction or input"
                else:
                    profile.status = "crashed"
                    profile.error = f"Tool exited with status {process.returncode}"
            else:
                profile.status = "completed"
            return profile

    @classmethod
    def _install_dependencies(cls, bwrap: str, sandbox_root: Path) -> None:
        deps_dir = sandbox_root / ".deps"
        deps_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(deps_dir, 0o777)
        except OSError:
            pass

        manifest_arg: list[str] | None = None
        if (sandbox_root / "requirements.txt").exists():
            manifest_arg = ["-r", "/workspace/requirements.txt"]
        elif (sandbox_root / "pyproject.toml").exists() or (sandbox_root / "setup.py").exists():
            manifest_arg = ["/workspace"]
        else:
            for req in sorted(sandbox_root.rglob("requirements.txt")):
                if ".git" not in req.parts:
                    manifest_arg = ["-r", f"/workspace/{req.relative_to(sandbox_root).as_posix()}"]
                    break
            if not manifest_arg:
                for pyproj in sorted(sandbox_root.rglob("pyproject.toml")):
                    if ".git" not in pyproj.parts:
                        pkg_dir = pyproj.parent.relative_to(sandbox_root).as_posix()
                        manifest_arg = [f"/workspace/{pkg_dir}" if pkg_dir != "." else "/workspace"]
                        break

        if not manifest_arg:
            return

        cmd = [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--target", "/workspace/.deps", *manifest_arg]
        sandbox_install_cmd = cls._sandbox_network_command(bwrap, sandbox_root, cmd)
        try:
            subprocess.run(
                sandbox_install_cmd,
                cwd=str(sandbox_root),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60,
            )
            for dirpath, _, _ in os.walk(deps_dir):
                try:
                    os.chmod(dirpath, 0o777)
                except OSError:
                    pass
        except Exception:
            pass

    @classmethod
    def _sandbox_network_command(cls, bwrap: str, root: Path, inner_command: list[str]) -> list[str]:
        args = [
            bwrap, "--die-with-parent", "--new-session",
            "--unshare-ipc", "--unshare-pid", "--unshare-uts",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--bind", str(root), "/workspace"
        ]
        for system_path in ("/usr", "/etc"):
            if Path(system_path).exists():
                args.extend(["--ro-bind", system_path, system_path])
        for link_path in ("/bin", "/sbin", "/lib", "/lib64"):
            link = Path(link_path)
            if not link.exists():
                continue
            if link.is_symlink():
                destination = os.readlink(link_path)
                if destination.startswith("/"):
                    destination = destination[1:]
                args.extend(["--symlink", destination, link_path])
            else:
                args.extend(["--ro-bind", link_path, link_path])
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            args.extend(["--uid", "65534", "--gid", "65534"])
        executable = Path(inner_command[0]).resolve() if inner_command else None
        if executable and executable.exists() and not str(executable).startswith(("/usr/", "/bin/", "/lib/")):
            environment_root = executable.parent.parent if executable.parent.name in {"bin", "Scripts"} else executable.parent
            parent = environment_root.parent
            chain: list[Path] = []
            while parent != parent.parent and parent not in {Path("/"), Path("")}:
                chain.append(parent)
                parent = parent.parent
            for directory in reversed(chain):
                args.extend(["--dir", str(directory)])
            args.extend(["--ro-bind", str(environment_root), str(environment_root)])
        args.extend(["--chdir", "/workspace", "--setenv", "HOME", "/tmp", "--"])
        return args + inner_command

    @staticmethod
    def _default_command(target: Path, root: Path) -> list[str]:
        if target.is_file():
            if target.suffix.lower() != ".py":
                raise ValueError("Runtime verification currently supports Python files only")
            return [sys.executable, f"/workspace/{target.relative_to(root).as_posix()}"]
        candidates = []
        for name in ("server.py", "main.py", "app.py"):
            candidates.append(root / name)
        for name in ("server.py", "main.py", "app.py"):
            candidates.extend(sorted(root.rglob(name)))
        all_py = [p for p in sorted(root.rglob("*.py")) if ".git" not in p.parts and "__pycache__" not in p.parts and "test" not in p.name.lower()]
        server_py = [p for p in all_py if "client" not in str(p).lower() and ("server" in str(p).lower() or "mcp" in str(p).lower())]
        non_client_py = [p for p in all_py if "client" not in str(p).lower()]
        candidates.extend(server_py)
        candidates.extend(non_client_py)
        candidates.extend(all_py)
        entrypoint = next((path for path in candidates if path.exists() and path.is_file()), None)
        if not entrypoint:
            raise ValueError("No Python entrypoint found; pass an explicit command")
        return [sys.executable, f"/workspace/{entrypoint.relative_to(root).as_posix()}"]

    @staticmethod
    def _sandbox_command(bwrap: str, root: Path, inner_command: list[str]) -> list[str]:
        # The workspace is already a disposable copy created by capture(); a
        # writable bind here lets the trace observe writes without exposing
        # the caller's checkout to the target process.
        args = [bwrap, "--die-with-parent", "--new-session", "--unshare-all", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--bind", str(root), "/workspace"]
        # Modern Ubuntu systems make /bin, /lib, and /lib64 symlinks into
        # /usr.  Recreating those links is more portable than trying to bind
        # mount a symlink onto itself inside bwrap's empty root.
        for system_path in ("/usr", "/etc"):
            if Path(system_path).exists():
                args.extend(["--ro-bind", system_path, system_path])
        for link_path in ("/bin", "/sbin", "/lib", "/lib64"):
            link = Path(link_path)
            if not link.exists():
                continue
            if link.is_symlink():
                destination = os.readlink(link_path)
                if destination.startswith("/"):
                    destination = destination[1:]
                args.extend(["--symlink", destination, link_path])
            else:
                args.extend(["--ro-bind", link_path, link_path])
        # GitHub-hosted runners may require bwrap to be launched with sudo to
        # create namespaces.  Even then, never run the target as root inside
        # the sandbox; map it to the unprivileged nobody account.
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            args.extend(["--uid", "65534", "--gid", "65534"])
        # A CI virtualenv may live outside /usr. Bind only its environment,
        # creating destination parents first, rather than exposing /home or
        # another broad host directory.
        executable = Path(inner_command[0]).resolve() if inner_command else None
        if executable and executable.exists() and not str(executable).startswith(("/usr/", "/bin/", "/lib/")):
            environment_root = executable.parent.parent if executable.parent.name in {"bin", "Scripts"} else executable.parent
            parent = environment_root.parent
            chain: list[Path] = []
            while parent != parent.parent and parent not in {Path("/"), Path("")}:
                chain.append(parent)
                parent = parent.parent
            for directory in reversed(chain):
                args.extend(["--dir", str(directory)])
            args.extend(["--ro-bind", str(environment_root), str(environment_root)])
        args.extend(["--chdir", "/workspace", "--setenv", "PYTHONPATH", "/workspace/.deps:/workspace:/workspace/src", "--setenv", "HOME", "/tmp", "--"])
        return args + inner_command

    @classmethod
    def _parse_traces(cls, target: Path, trace_dir: str, *, ignored_processes: set[str] | None = None) -> RuntimeProfile:
        profile = RuntimeProfile(target=str(target), status="not_run")
        files: dict[str, set[str]] = {}
        networks: dict[tuple[str, str, int | None], RuntimeNetworkAccess] = {}
        processes: dict[str, RuntimeProcess] = {}
        for trace_path in sorted(Path(trace_dir).glob("trace*")):
            try:
                lines = trace_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
            for line in lines:
                cls._parse_file(line, files)
                cls._parse_network(line, networks)
                cls._parse_process(line, processes, ignored_processes or set())
        profile.files_touched = [RuntimeFileAccess(path=path, modes=sorted(modes)) for path, modes in sorted(files.items())]
        profile.network_connections = list(networks.values())
        profile.subprocesses = list(processes.values())
        profile.system_resources = sorted({path for path in files if cls._is_sensitive_system_resource(path)})
        return profile

    @staticmethod
    def _is_sensitive_system_resource(path: str) -> bool:
        lower = path.lower().replace("\\", "/")
        return lower.startswith(("/etc/passwd", "/etc/shadow", "/root/", "/home/"))

    @staticmethod
    def _parse_file(line: str, files: dict[str, set[str]]) -> None:
        match = re.search(r"\b(openat|open|creat)\([^,]+,\s*\"([^\"]+)\"([^)]*)\)", line)
        if not match:
            return
        path, tail = match.group(2), match.group(3)
        mode = "write" if any(flag in tail for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")) else "read"
        files.setdefault(path, set()).add(mode)

    @staticmethod
    def _parse_network(line: str, networks: dict[tuple[str, str, int | None], RuntimeNetworkAccess]) -> None:
        match = re.search(r"\b(connect|bind)\([^\n]*?sa_family=([A-Z0-9_]+),\s*.*?sin_port=htons\((\d+)\).*?(?:inet_addr|inet_pton)\(\"([^\"]+)\"\)", line)
        if not match:
            return
        operation, family, port, address = match.group(1), match.group(2), int(match.group(3)), match.group(4)
        networks[(operation, address, port)] = RuntimeNetworkAccess(operation=operation, address=address, port=port, family=family)

    @staticmethod
    def _parse_process(line: str, processes: dict[str, RuntimeProcess], ignored_processes: set[str]) -> None:
        match = re.search(r"\bexecve\(\"([^\"]+)\",\s*\[([^\]]*)\]", line)
        if not match:
            return
        executable = match.group(1)
        if executable in ignored_processes:
            return
        arguments = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', match.group(2))
        processes.setdefault(executable, RuntimeProcess(executable=executable, arguments=arguments))


def capture_runtime(repo_path: Path, timeout_seconds: float = 10.0, *, command: Sequence[str] | None = None, input_payload: dict | None = None) -> RuntimeProfile:
    return RuntimeCapture(timeout_seconds=timeout_seconds).capture(repo_path, command=command, input_payload=input_payload)
