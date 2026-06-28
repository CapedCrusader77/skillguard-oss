import re
from pathlib import Path
from typing import List
from skillguard.models.finding import Finding
from skillguard.core.constants import RULE_METADATA

class JavaScriptScanner:
    """
    Regex-based scanner for JavaScript source files.
    Identifies command execution, network activity, filesystem operations, and env access.
    """
    def __init__(self, file_path: Path, project_root: Path):
        self.file_path = file_path
        self.project_root = project_root
        try:
            self.relative_path = str(file_path.relative_to(project_root)).replace("\\", "/")
        except ValueError:
            self.relative_path = str(file_path).replace("\\", "/")
        self.findings: List[Finding] = []

    def scan(self) -> List[Finding]:
        try:
            content = self.file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            # Skip unreadable files robustly
            return []

        lines = content.splitlines()
        in_block_comment = False
        
        # Pre-compiled regexes
        # Command executions
        re_spawn = re.compile(r"\bspawn\s*\(")
        re_exec_sync = re.compile(r"\bexecSync\s*\(")
        re_exec = re.compile(r"\bexec\s*\(")
        
        # Filesystems
        re_fs_read = re.compile(r"\bfs\.readFile\b")
        re_fs_write = re.compile(r"\bfs\.writeFile\b")
        re_fs_open = re.compile(r"\bfs\.open\b")
        
        # Networks
        re_fetch = re.compile(r"\bfetch\s*\(")
        re_axios = re.compile(r"\baxios\b")
        re_http_req = re.compile(r"\bhttp\.request\b")
        re_https_req = re.compile(r"\bhttps\.request\b")
        
        # Secrets / Env access
        re_process_env = re.compile(r"\bprocess\.env\b")

        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            
            # Multi-line comment parsing block
            if in_block_comment:
                if "*/" in clean_line:
                    in_block_comment = False
                    clean_line = clean_line.split("*/", 1)[1]
                else:
                    continue
            
            if "/*" in clean_line:
                if "*/" in clean_line:
                    clean_line = re.sub(r"/\*.*?\*/", "", clean_line)
                else:
                    in_block_comment = True
                    clean_line = clean_line.split("/*", 1)[0]

            # Strip single line comments (but not http:// or https:// URLs)
            # Find // only if it isn't part of ://
            if "//" in clean_line:
                # Match // not preceded by a colon
                clean_line = re.sub(r"(?<!:)//.*$", "", clean_line)

            if not clean_line.strip():
                continue

            # Match patterns
            # 1. Command executions
            if re_spawn.search(clean_line):
                self._add_finding("child_process.spawn", idx)
            elif re_exec_sync.search(clean_line):
                self._add_finding("child_process.execSync", idx)
            elif re_exec.search(clean_line):
                self._add_finding("child_process.exec", idx)

            # 2. Filesystem APIs
            if re_fs_read.search(clean_line):
                self._add_finding("fs.readFile", idx)
            if re_fs_write.search(clean_line):
                self._add_finding("fs.writeFile", idx)
            if re_fs_open.search(clean_line):
                self._add_finding("fs.open", idx)

            # 3. Network APIs
            if re_fetch.search(clean_line):
                self._add_finding("fetch", idx)
            if re_axios.search(clean_line):
                self._add_finding("axios", idx)
            if re_http_req.search(clean_line):
                self._add_finding("http.request", idx)
            if re_https_req.search(clean_line):
                self._add_finding("https.request", idx)

            # 4. Secrets
            if re_process_env.search(clean_line):
                self._add_finding("process.env", idx)

        return self.findings

    def _add_finding(self, rule_name: str, line_no: int):
        meta = RULE_METADATA[rule_name]
        finding = Finding(
            id=meta["id"],
            severity=meta["severity"],
            category=meta["category"],
            file=self.relative_path,
            line=line_no,
            message=meta["message"]
        )
        self.findings.append(finding)
