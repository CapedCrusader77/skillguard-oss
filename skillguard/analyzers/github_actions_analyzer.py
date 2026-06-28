import os
import re
from pathlib import Path
from typing import List

from skillguard.analyzers.base import BaseAnalyzer, register_analyzer
from skillguard.models.finding import Finding

@register_analyzer
class GithubActionsAnalyzer(BaseAnalyzer):
    """
    Scans GitHub Actions workflow YAML files for supply chain vulnerabilities:
    - Remote script downloads and runs (curl/wget | bash)
    - Untrusted/unpinned third-party actions (not pinned to commit SHA)
    - Hardcoded secrets or tokens in environment blocks.
    """
    def analyze(self, repo_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        
        # Discover workflows in .github/workflows/
        discovered = []
        workflow_dir = repo_path / ".github" / "workflows"
        
        # Also check if target is a file itself and matches workflow yaml
        if repo_path.is_file():
            if repo_path.suffix in {".yml", ".yaml"} and ".github/workflows" in str(repo_path.resolve()):
                discovered.append(repo_path)
            project_root = repo_path.parent
        else:
            project_root = repo_path
            if workflow_dir.exists() and workflow_dir.is_dir():
                for root, _, files in os.walk(workflow_dir):
                    for file in files:
                        if file.endswith(".yml") or file.endswith(".yaml"):
                            discovered.append(Path(root) / file)

        for file_path in discovered:
            try:
                rel_path = str(file_path.relative_to(project_root)).replace("\\", "/")
            except ValueError:
                rel_path = str(file_path).replace("\\", "/")
                
            self._scan_workflow(file_path, rel_path, findings)

        return findings

    def _scan_workflow(self, file_path: Path, rel_path: str, findings: List[Finding]):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        lines = content.splitlines()

        # Regex patterns
        re_remote_script = re.compile(r"\b(curl|wget).*\|\s*(bash|sh)\b", re.IGNORECASE)
        re_uses = re.compile(r"^(?:-\s*)?uses\s*:\s*([^#\s]+)")
        re_sha = re.compile(r"^[a-fA-F0-9]{40}$")
        
        # Pattern for potential exposed hardcoded secrets in YAML env/with fields
        re_yaml_secret = re.compile(
            r"(token|password|secret|key|passwd|auth)\s*:\s*[\"']?([^\"'\$\{\}\s][^\"'\s]{10,})[\"']?",
            re.IGNORECASE
        )
        # Match common API key prefix strings
        re_pat = re.compile(r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}")
        re_openai = re.compile(r"sk-[a-zA-Z0-9]{48}")

        for line_no, line in enumerate(lines, 1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue

            # Check: Remote script execution (curl/wget | bash)
            if re_remote_script.search(clean_line):
                findings.append(Finding(
                    id="GHA001",
                    severity="CRITICAL",
                    confidence="HIGH",
                    category="SUPPLY_CHAIN",
                    file=rel_path,
                    line=line_no,
                    message="Remote script execution (curl/wget piped to bash/sh) detected in workflow step"
                ))

            # Check: Uses directive with unpinned action
            uses_match = re_uses.match(clean_line)
            if uses_match:
                action_ref = uses_match.group(1).strip()
                if not (action_ref.startswith("./") or action_ref.startswith("/") or action_ref.startswith("docker://")):
                    if "@" in action_ref:
                        action, version = action_ref.split("@", 1)
                        if not re_sha.match(version):
                            findings.append(Finding(
                                id="GHA002",
                                severity="MEDIUM",
                                confidence="HIGH",
                                category="SUPPLY_CHAIN",
                                file=rel_path,
                                line=line_no,
                                message=f"Action not pinned to immutable commit SHA: '{action}' (current version: '{version}')"
                            ))
                    else:
                        findings.append(Finding(
                            id="GHA002",
                            severity="MEDIUM",
                            confidence="HIGH",
                            category="SUPPLY_CHAIN",
                            file=rel_path,
                            line=line_no,
                            message=f"Action does not specify a version or commit SHA: '{action_ref}'"
                        ))

            # Check: Secret exposure inside YAML env/args
            secret_match = re_yaml_secret.search(clean_line)
            if secret_match:
                key, val = secret_match.group(1), secret_match.group(2)
                if not ("secrets." in val or "env." in val or "steps." in val or "github." in val):
                    findings.append(Finding(
                        id="GHA003",
                        severity="CRITICAL",
                        confidence="MEDIUM",
                        category="SUPPLY_CHAIN",
                        file=rel_path,
                        line=line_no,
                        message=f"Potential hardcoded token or secret detected in parameter '{key}'"
                    ))
            elif re_pat.search(clean_line) or re_openai.search(clean_line):
                findings.append(Finding(
                    id="GHA003",
                    severity="CRITICAL",
                    confidence="HIGH",
                    category="SUPPLY_CHAIN",
                    file=rel_path,
                    line=line_no,
                    message="Hardcoded API token or credential string detected in workflow file"
                ))
