import os
import re
from pathlib import Path
from typing import List

from skillguard.analyzers.base import BaseAnalyzer, register_analyzer
from skillguard.models.finding import Finding
from skillguard.core.repository_discovery import IGNORE_DIRS

SUPPORTED_SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".json", ".yml", ".yaml", 
    ".env", ".ini", ".conf", ".txt", ".md", ".sh", ".bash"
}

@register_analyzer
class SecretAnalyzer(BaseAnalyzer):
    """
    Scans source files, config files, and environment files for hardcoded secrets,
    API keys, and password credentials.
    """
    def analyze(self, repo_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        
        # Discover files to scan
        discovered = []
        if repo_path.is_file():
            if repo_path.suffix in SUPPORTED_SCAN_EXTENSIONS or repo_path.name.startswith(".env"):
                discovered.append(repo_path)
            project_root = repo_path.parent
        else:
            project_root = repo_path
            for root, dirs, files in os.walk(repo_path):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
                for file in files:
                    file_path = Path(root) / file
                    if file_path.suffix in SUPPORTED_SCAN_EXTENSIONS or file.startswith(".env"):
                        discovered.append(file_path)

        for file_path in discovered:
            try:
                rel_path = str(file_path.relative_to(project_root)).replace("\\", "/")
            except ValueError:
                rel_path = str(file_path).replace("\\", "/")
                
            self._scan_file_for_secrets(file_path, rel_path, findings)

        return findings

    def _scan_file_for_secrets(self, file_path: Path, rel_path: str, findings: List[Finding]):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        lines = content.splitlines()

        # Secret Regexes
        rules = {
            "OpenAI API Key": re.compile(r"\bsk-(?:proj-)?[a-zA-Z0-9]{32,}\b"),
            "GitHub PAT": re.compile(r"\bghp_[a-zA-Z0-9]{36}\b|\bgithub_pat_[a-zA-Z0-9_]{82}\b"),
            "AWS Access Key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            "Google API Key": re.compile(r"\bAIzaSy[a-zA-Z0-9_\-]{33}\b"),
            "JWT Token": re.compile(r"\beyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+"),
            "Generic Bearer Token": re.compile(r"\bBearer\s+[a-zA-Z0-9_\-\.\~+/]+=*\b", re.IGNORECASE),
            # Password/Key Assignments: token="some-value" or PASSWORD='secret-value'
            "Hardcoded Password/Key Assignment": re.compile(
                r"\b[a-zA-Z0-9_]*(password|pass|passwd|token|apikey|api_key|secret|private_key|client_secret)[a-zA-Z0-9_]*\s*(?:=|:)\s*[\"']([^\"'\$\{\}\s]{8,})[\"']",
                re.IGNORECASE
            )
        }

        # Avoid duplicate findings on the same line
        for line_no, line in enumerate(lines, 1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#") or clean_line.startswith("//"):
                continue

            for name, pattern in rules.items():
                match = pattern.search(clean_line)
                if match:
                    # For password assignments, ignore if it looks like an environment variable reference
                    if name == "Hardcoded Password/Key Assignment":
                        val = match.group(2)
                        if "env" in val.lower() or "get" in val.lower() or "sys" in val.lower():
                            continue
                        message = f"Hardcoded credential detected: Potential secret assignment in '{match.group(1)}'"
                        confidence = "MEDIUM"
                    else:
                        message = f"Hardcoded credential detected: {name}"
                        confidence = "HIGH"

                    findings.append(Finding(
                        id="SEC101",
                        severity="CRITICAL",
                        confidence=confidence,
                        category="SECRET_ACCESS",
                        file=rel_path,
                        line=line_no,
                        message=message
                    ))
                    break
