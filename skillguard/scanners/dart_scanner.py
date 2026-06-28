import re
from pathlib import Path
from typing import List
from skillguard.models.finding import Finding
from skillguard.core.constants import RULE_METADATA


class DartScanner:
    """
    Regex-based scanner for Dart/Flutter source files (.dart).
    Identifies command execution, network activity, filesystem operations,
    and environment variable access patterns.
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
            return []

        lines = content.splitlines()
        in_block_comment = False

        # Pre-compiled regex patterns

        # Command Execution — Process.run / Process.start
        re_process_run   = re.compile(r"\bProcess\.run\b")
        re_process_start = re.compile(r"\bProcess\.start\b")

        # Filesystem — File / Directory constructors
        re_file      = re.compile(r"\bFile\s*\(")
        re_directory = re.compile(r"\bDirectory\s*\(")

        # Network — http package get/post + Dio
        re_http_get  = re.compile(r"\bhttp\.get\b")
        re_http_post = re.compile(r"\bhttp\.post\b")
        re_dio       = re.compile(r"\bDio\s*\(|\bDio\b")

        # Environment — Platform.environment
        re_platform_env = re.compile(r"\bPlatform\.environment\b")

        for idx, line in enumerate(lines, 1):
            clean = line.strip()

            # Block comment tracking
            if in_block_comment:
                if "*/" in clean:
                    in_block_comment = False
                    clean = clean.split("*/", 1)[1]
                else:
                    continue

            if "/*" in clean:
                if "*/" in clean:
                    clean = re.sub(r"/\*.*?\*/", "", clean)
                else:
                    in_block_comment = True
                    clean = clean.split("/*", 1)[0]

            # Strip single-line comments (// not inside http://)
            if "//" in clean:
                clean = re.sub(r"(?<!:)//.*$", "", clean)

            if not clean.strip():
                continue

            # 1. Command Execution
            if re_process_run.search(clean):
                self._add_finding("dart.Process.run", idx)
            if re_process_start.search(clean):
                self._add_finding("dart.Process.start", idx)

            # 2. Filesystem
            if re_file.search(clean):
                self._add_finding("dart.File", idx)
            if re_directory.search(clean):
                self._add_finding("dart.Directory", idx)

            # 3. Network
            if re_http_get.search(clean):
                self._add_finding("dart.http.get", idx)
            if re_http_post.search(clean):
                self._add_finding("dart.http.post", idx)
            if re_dio.search(clean):
                self._add_finding("dart.Dio", idx)

            # 4. Environment
            if re_platform_env.search(clean):
                self._add_finding("dart.Platform.environment", idx)

        return self.findings

    def _add_finding(self, rule_name: str, line_no: int) -> None:
        meta = RULE_METADATA[rule_name]
        self.findings.append(Finding(
            id=meta["id"],
            severity=meta["severity"],
            category=meta["category"],
            file=self.relative_path,
            line=line_no,
            message=meta["message"],
        ))
