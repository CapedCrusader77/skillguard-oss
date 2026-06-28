import os
import json
import re
from enum import Enum
from pathlib import Path
from typing import List, Set, Dict

class ProjectType(str, Enum):
    FRONTEND = "Frontend App"
    BACKEND = "Backend API"
    CLI = "CLI Tool"
    SECURITY_SCANNER = "Security Scanner"
    MCP_SERVER = "MCP Server"
    BROWSER_EXTENSION = "Browser Extension"
    BLOCKCHAIN = "Blockchain Project"
    GENERIC = "Generic"

class Capability(str, Enum):
    NETWORK = "Network Access"
    FILESYSTEM = "Filesystem Access"
    ENVIRONMENT = "Environment Variable Access"
    DATABASE = "Database Access"
    BROWSER = "Browser Automation"
    COMMAND = "Command Execution"
    CONTAINER = "Container Management"
    GIT = "Git Operations"

EXPECTED_CAPABILITIES: Dict[ProjectType, Set[Capability]] = {
    ProjectType.FRONTEND: {Capability.NETWORK, Capability.ENVIRONMENT},
    ProjectType.BACKEND: {Capability.NETWORK, Capability.ENVIRONMENT, Capability.FILESYSTEM, Capability.DATABASE},
    ProjectType.CLI: {Capability.FILESYSTEM, Capability.ENVIRONMENT, Capability.COMMAND, Capability.GIT},
    ProjectType.SECURITY_SCANNER: {Capability.FILESYSTEM, Capability.ENVIRONMENT, Capability.GIT},
    ProjectType.MCP_SERVER: {Capability.NETWORK, Capability.ENVIRONMENT, Capability.FILESYSTEM},
    ProjectType.BROWSER_EXTENSION: {Capability.NETWORK},
    ProjectType.BLOCKCHAIN: {Capability.NETWORK, Capability.ENVIRONMENT, Capability.DATABASE},
    ProjectType.GENERIC: {Capability.NETWORK, Capability.FILESYSTEM, Capability.ENVIRONMENT},
}

class ProjectProfiler:
    def profile_project(self, repo_path: Path) -> ProjectType:
        root_dir = repo_path.parent if repo_path.is_file() else repo_path
        
        # 1. Direct path matches (e.g. self-scanning or containing folder names)
        path_str = str(root_dir.resolve()).lower()
        if "skillguard" in path_str:
            return ProjectType.SECURITY_SCANNER

        # 2. Check for Manifest.json (Browser extension)
        manifest_path = root_dir / "manifest.json"
        if manifest_path.exists():
            try:
                manifest_data = json.loads(manifest_path.read_text(encoding="utf-8", errors="ignore"))
                if "manifest_version" in manifest_data:
                    return ProjectType.BROWSER_EXTENSION
            except Exception:
                pass

        # Gather package.json / requirements.txt / pyproject.toml contents
        dep_text = ""
        combined_text = ""

        pkg_json = root_dir / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                dep_text += " " + " ".join(deps.keys())
                combined_text += " " + data.get("name", "") + " " + data.get("description", "")
            except Exception:
                pass

        req_txt = root_dir / "requirements.txt"
        if req_txt.exists():
            try:
                dep_text += " " + req_txt.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

        pyproject = root_dir / "pyproject.toml"
        if pyproject.exists():
            try:
                dep_text += " " + pyproject.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                pass

        readme_files = [root_dir / "README.md", root_dir / "README.txt", root_dir / "readme.md", root_dir / "readme.txt"]
        for rf in readme_files:
            if rf.exists():
                try:
                    combined_text += " " + rf.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    pass

        lower_deps = dep_text.lower()
        lower_text = combined_text.lower()

        # 3. Check for MCP Server
        if "@modelcontextprotocol/sdk" in lower_deps or "mcp-server" in lower_deps or "mcp" in lower_deps:
            return ProjectType.MCP_SERVER
        if "mcp server" in lower_text or "model context protocol" in lower_text:
            return ProjectType.MCP_SERVER

        # 4. Check for Blockchain
        blockchain_deps = ["ethers", "web3", "solidity", "@openzeppelin/contracts", "solc", "anchor-lang", "bitcoin"]
        if any(b in lower_deps for b in blockchain_deps):
            return ProjectType.BLOCKCHAIN
        if "blockchain" in lower_text or "smart contract" in lower_text or "solidity" in lower_text:
            return ProjectType.BLOCKCHAIN

        # 5. Check for Security Scanner / Linters
        scanner_deps = ["bandit", "eslint", "semgrep", "radon", "skillguard"]
        if any(s in lower_deps for s in scanner_deps):
            return ProjectType.SECURITY_SCANNER
        if "linter" in lower_text or "security scanner" in lower_text or "static analysis" in lower_text:
            return ProjectType.SECURITY_SCANNER

        # 6. Check for CLI Tool
        cli_deps = ["click", "typer", "argparse", "commander", "yargs"]
        if any(c in lower_deps for c in cli_deps):
            return ProjectType.CLI
        if "cli tool" in lower_text or "command line tool" in lower_text or "terminal tool" in lower_text:
            return ProjectType.CLI

        # 7. Check for Backend APIs
        backend_deps = ["express", "django", "fastapi", "flask", "nestjs", "spring-boot", "rails", "koa"]
        if any(b in lower_deps for b in backend_deps):
            return ProjectType.BACKEND
        if "backend api" in lower_text or "backend service" in lower_text or "api server" in lower_text:
            return ProjectType.BACKEND

        # 8. Check for Frontend Apps
        frontend_deps = ["react", "vue", "svelte", "next", "astro", "vite", "nuxt", "angular"]
        if any(f in lower_deps for f in frontend_deps):
            return ProjectType.FRONTEND
        if "frontend app" in lower_text or "single page application" in lower_text or "next.js app" in lower_text:
            return ProjectType.FRONTEND

        return ProjectType.GENERIC

    def get_unexpected_capabilities(self, project_type: ProjectType, active_capabilities: Set[Capability]) -> Set[Capability]:
        expected = EXPECTED_CAPABILITIES.get(project_type, set())
        return active_capabilities - expected
