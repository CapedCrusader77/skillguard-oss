import os
import re
from pathlib import Path
from typing import List

from skillguard.analyzers.base import BaseAnalyzer, register_analyzer
from skillguard.models.finding import Finding
from skillguard.core.repository_discovery import IGNORE_DIRS

@register_analyzer
class DockerfileAnalyzer(BaseAnalyzer):
    """
    Scans Dockerfiles for dangerous patterns, root execution, and remote scripts executions.
    """
    def analyze(self, repo_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        
        # Discover Dockerfiles
        discovered = []
        if repo_path.is_file():
            if repo_path.name == "Dockerfile" or repo_path.name.startswith("Dockerfile."):
                discovered.append(repo_path)
            project_root = repo_path.parent
        else:
            project_root = repo_path
            for root, dirs, files in os.walk(repo_path):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
                for file in files:
                    if file == "Dockerfile" or file.startswith("Dockerfile."):
                        discovered.append(Path(root) / file)

        for file_path in discovered:
            try:
                rel_path = str(file_path.relative_to(project_root)).replace("\\", "/")
            except ValueError:
                rel_path = str(file_path).replace("\\", "/")
                
            self._scan_dockerfile(file_path, rel_path, findings)

        return findings

    def _scan_dockerfile(self, file_path: Path, rel_path: str, findings: List[Finding]):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        lines = content.splitlines()
        has_user_directive = False
        last_user = None

        # Regex patterns
        re_remote_script = re.compile(r"RUN\s+.*(curl|wget).*\|\s*(bash|sh)\b", re.IGNORECASE)
        re_add_url = re.compile(r"ADD\s+https?://", re.IGNORECASE)
        re_chmod_777 = re.compile(r"chmod\s+(?:-R\s+)?777\b", re.IGNORECASE)
        re_privileged = re.compile(r"\b--privileged\b", re.IGNORECASE)
        re_user = re.compile(r"^USER\s+(\S+)", re.IGNORECASE)

        for line_no, line in enumerate(lines, 1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue

            # Track USER directives
            user_match = re_user.match(clean_line)
            if user_match:
                has_user_directive = True
                last_user = user_match.group(1).strip().lower()

            # Check: Remote script execution during build (curl/wget piped to bash/sh)
            if re_remote_script.search(clean_line):
                findings.append(Finding(
                    id="DKR003",
                    severity="CRITICAL",
                    confidence="HIGH",
                    category="CONTAINER_SECURITY",
                    file=rel_path,
                    line=line_no,
                    message="Remote script execution during build (curl/wget piped to bash/sh) detected"
                ))

            # Check: ADD remote URLs
            if re_add_url.search(clean_line):
                findings.append(Finding(
                    id="DKR004",
                    severity="HIGH",
                    confidence="HIGH",
                    category="CONTAINER_SECURITY",
                    file=rel_path,
                    line=line_no,
                    message="ADD instruction used with remote URL (use curl or wget in RUN instead)"
                ))

            # Check: chmod 777
            if re_chmod_777.search(clean_line):
                findings.append(Finding(
                    id="DKR005",
                    severity="HIGH",
                    confidence="HIGH",
                    category="CONTAINER_SECURITY",
                    file=rel_path,
                    line=line_no,
                    message="Overly permissive file permissions (chmod 777) detected"
                ))

            # Check: Privileged container flag in RUN/ENV
            if re_privileged.search(clean_line):
                findings.append(Finding(
                    id="DKR006",
                    severity="HIGH",
                    confidence="HIGH",
                    category="CONTAINER_SECURITY",
                    file=rel_path,
                    line=line_no,
                    message="Privileged container flag or run parameter detected"
                ))

        # Check: final container run user security
        if has_user_directive:
            if last_user in {"root", "0"}:
                findings.append(Finding(
                    id="DKR001",
                    severity="HIGH",
                    confidence="HIGH",
                    category="CONTAINER_SECURITY",
                    file=rel_path,
                    line=len(lines),
                    message="Container configured to run as root user"
                ))
        else:
            findings.append(Finding(
                id="DKR002",
                severity="MEDIUM",
                confidence="HIGH",
                category="CONTAINER_SECURITY",
                file=rel_path,
                line=1,
                message="No USER instruction found; container runs as root by default"
            ))
