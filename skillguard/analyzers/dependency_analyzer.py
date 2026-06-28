import os
import json
import re
from pathlib import Path
from typing import List, Set

from skillguard.analyzers.base import BaseAnalyzer, register_analyzer
from skillguard.models.finding import Finding
from skillguard.core.repository_discovery import IGNORE_DIRS

TYPOSQUATS = {
    "requestss",
    "cryptographyy",
    "pytzz",
    "pydantice",
    "numpyy",
    "reqeusts",
    "pandy",
}

EXCESSIVE_PERM_PACKAGES = {
    "pycurl",
    "paramiko",
    "winreg",
    "win32api",
    "pywin32",
}

@register_analyzer
class DependencyAnalyzer(BaseAnalyzer):
    """
    Scans dependency files for security risks such as typosquatting, duplicates,
    and packages with excessive system permissions.
    """
    def analyze(self, repo_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        target_files = {
            "requirements.txt",
            "requirements-dev.txt",
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "poetry.lock",
            "uv.lock",
        }
        
        # Discover target dependency files in the repo path
        discovered = []
        if repo_path.is_file():
            if repo_path.name in target_files:
                discovered.append(repo_path)
            project_root = repo_path.parent
        else:
            project_root = repo_path
            for root, dirs, files in os.walk(repo_path):
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
                for file in files:
                    if file in target_files:
                        discovered.append(Path(root) / file)

        for file_path in discovered:
            try:
                rel_path = str(file_path.relative_to(project_root)).replace("\\", "/")
            except ValueError:
                rel_path = str(file_path).replace("\\", "/")

            if file_path.name.startswith("requirements"):
                self._analyze_requirements(file_path, rel_path, findings)
            elif file_path.name == "package.json":
                self._analyze_package_json(file_path, rel_path, findings)
            else:
                self._analyze_lockfiles(file_path, rel_path, findings)

        return findings

    def _analyze_requirements(self, file_path: Path, rel_path: str, findings: List[Finding]):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        packages_seen = {}
        for line_no, line in enumerate(content.splitlines(), 1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#") or clean_line.startswith("-"):
                continue
                
            # Parse package name (e.g. requests==2.28.1 -> requests)
            match = re.match(r"^([a-zA-Z0-9_\-\[\]]+)", clean_line)
            if not match:
                continue
                
            package_name = match.group(1).lower()
            
            # Check typosquatting
            if package_name in TYPOSQUATS:
                findings.append(Finding(
                    id="DEP001",
                    severity="HIGH",
                    confidence="HIGH",
                    category="SUPPLY_CHAIN",
                    file=rel_path,
                    line=line_no,
                    message=f"Potential typosquat package detected: '{package_name}'"
                ))

            # Check duplicate packages
            if package_name in packages_seen:
                findings.append(Finding(
                    id="DEP002",
                    severity="MEDIUM",
                    confidence="HIGH",
                    category="SUPPLY_CHAIN",
                    file=rel_path,
                    line=line_no,
                    message=f"Duplicate dependency detected: '{package_name}' (previously seen on line {packages_seen[package_name]})"
                ))
            else:
                packages_seen[package_name] = line_no

            # Check excessive permissions
            if package_name in EXCESSIVE_PERM_PACKAGES:
                findings.append(Finding(
                    id="DEP003",
                    severity="MEDIUM",
                    confidence="HIGH",
                    category="SUPPLY_CHAIN",
                    file=rel_path,
                    line=line_no,
                    message=f"Dependency with excessive permissions detected: '{package_name}'"
                ))

    def _analyze_package_json(self, file_path: Path, rel_path: str, findings: List[Finding]):
        try:
            data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return

        deps = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})

        # Typosquats & excessive permission checks
        all_deps = {**deps, **dev_deps}
        for package_name in all_deps:
            package_name_lower = package_name.lower()
            if package_name_lower in TYPOSQUATS:
                findings.append(Finding(
                    id="DEP001",
                    severity="HIGH",
                    confidence="HIGH",
                    category="SUPPLY_CHAIN",
                    file=rel_path,
                    line=1,
                    message=f"Potential typosquat package detected in package.json: '{package_name}'"
                ))
            if package_name_lower in EXCESSIVE_PERM_PACKAGES:
                findings.append(Finding(
                    id="DEP003",
                    severity="MEDIUM",
                    confidence="HIGH",
                    category="SUPPLY_CHAIN",
                    file=rel_path,
                    line=1,
                    message=f"Dependency with excessive permissions detected in package.json: '{package_name}'"
                ))

        # Check duplicate packages in both deps and devDeps
        duplicates = set(deps.keys()).intersection(set(dev_deps.keys()))
        for pkg in duplicates:
            findings.append(Finding(
                id="DEP002",
                severity="MEDIUM",
                confidence="HIGH",
                category="SUPPLY_CHAIN",
                file=rel_path,
                line=1,
                message=f"Duplicate dependency detected: '{pkg}' is in both dependencies and devDependencies"
            ))

    def _analyze_lockfiles(self, file_path: Path, rel_path: str, findings: List[Finding]):
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        for pkg in TYPOSQUATS:
            pattern = re.compile(rf'["\']?{pkg}["\']?[:\s/]', re.IGNORECASE)
            if pattern.search(content):
                findings.append(Finding(
                    id="DEP001",
                    severity="HIGH",
                    confidence="HIGH",
                    category="SUPPLY_CHAIN",
                    file=rel_path,
                    line=1,
                    message=f"Potential typosquat package '{pkg}' referenced in lockfile"
                ))

        for pkg in EXCESSIVE_PERM_PACKAGES:
            pattern = re.compile(rf'["\']?{pkg}["\']?[:\s/]', re.IGNORECASE)
            if pattern.search(content):
                findings.append(Finding(
                    id="DEP003",
                    severity="MEDIUM",
                    confidence="HIGH",
                    category="SUPPLY_CHAIN",
                    file=rel_path,
                    line=1,
                    message=f"Dependency with excessive permissions '{pkg}' referenced in lockfile"
                ))
