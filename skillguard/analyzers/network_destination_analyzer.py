import os
import re
from pathlib import Path
from typing import List, Set

from skillguard.analyzers.base import BaseAnalyzer, register_analyzer
from skillguard.models.finding import Finding
from skillguard.core.repository_discovery import IGNORE_DIRS

SUPPORTED_CODE_EXTENSIONS = {".py", ".js", ".ts"}

@register_analyzer
class NetworkDestinationAnalyzer(BaseAnalyzer):
    """
    Scans source files (.py, .js, .ts) to extract external network destinations
    (domains, IPs, and URLs) referenced in network requests or configuration.
    """
    def analyze(self, repo_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        
        # Discover source files
        discovered = []
        if repo_path.is_file():
            if repo_path.suffix in SUPPORTED_CODE_EXTENSIONS:
                discovered.append(repo_path)
            project_root = repo_path.parent
        else:
            project_root = repo_path
            for root, dirs, files in os.walk(repo_path):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
                for file in files:
                    file_path = Path(root) / file
                    if file_path.suffix in SUPPORTED_CODE_EXTENSIONS:
                        discovered.append(file_path)

        for file_path in discovered:
            try:
                rel_path = str(file_path.relative_to(project_root)).replace("\\", "/")
            except ValueError:
                rel_path = str(file_path).replace("\\", "/")
                
            self._scan_file_for_destinations(file_path, rel_path, findings)

        return findings

    def _scan_file_for_destinations(self, file_path: Path, rel_path: str, findings: List[Finding]):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        lines = content.splitlines()
        re_url = re.compile(r'https?://([^/\s\'"\)`#\?]+)', re.IGNORECASE)
        network_keywords = {"requests", "fetch", "axios", "httpx", "urllib", "socket", "http", "https"}
        domains_seen: Set[str] = set()

        for line_no, line in enumerate(lines, 1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#") or clean_line.startswith("//"):
                continue

            matches = re_url.findall(clean_line)
            for domain in matches:
                domain = domain.strip().lower()
                
                if not domain or domain in {"localhost", "127.0.0.1", "0.0.0.0", "example.com"}:
                    continue
                
                has_context = any(kw in clean_line.lower() for kw in network_keywords)
                
                if has_context and domain not in domains_seen:
                    domains_seen.add(domain)
                    findings.append(Finding(
                        id="NET201",
                        severity="LOW",
                        confidence="MEDIUM",
                        category="NETWORK",
                        file=rel_path,
                        line=line_no,
                        message=f"External Destination: {domain}"
                    ))
