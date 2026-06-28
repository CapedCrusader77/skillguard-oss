import os
import json
import re
from enum import Enum
from pathlib import Path

class ProjectContext(str, Enum):
    SECURITY_SCANNER = "Security Scanner"
    MCP_SERVER = "MCP Server"
    CLI_TOOL = "CLI Tool"
    WEATHER_SERVICE = "Weather Service"
    DATABASE_TOOL = "Database Tool"
    GENERIC = "Generic"

class ContextAnalyzer:
    def analyze_context(self, repo_path: Path) -> ProjectContext:
        # 1. Check directory path name for self-scan awareness
        path_str = str(repo_path.resolve()).lower()
        if "skillguard" in path_str:
            return ProjectContext.SECURITY_SCANNER

        # 2. Extract description content to classify context
        root_dir = repo_path.parent if repo_path.is_file() else repo_path
        combined_text = ""

        # Try README
        readme_files = [root_dir / "README.md", root_dir / "README.txt", root_dir / "readme.md", root_dir / "readme.txt"]
        for rf in readme_files:
            if rf.exists():
                try:
                    combined_text += " " + rf.read_text(encoding="utf-8", errors="ignore")
                    break
                except Exception:
                    pass

        # Try package.json / pyproject.toml
        pkg_json = root_dir / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                combined_text += " " + data.get("name", "") + " " + data.get("description", "")
            except Exception:
                pass

        lower_text = combined_text.lower()

        # Keywords classifications
        if "security scanner" in lower_text or "static analysis" in lower_text or "auditor" in lower_text or "vulnerability scanner" in lower_text:
            return ProjectContext.SECURITY_SCANNER
        if "mcp server" in lower_text or "model context protocol" in lower_text:
            return ProjectContext.MCP_SERVER
        if "cli tool" in lower_text or "command line tool" in lower_text or "terminal tool" in lower_text:
            return ProjectContext.CLI_TOOL
        if "weather service" in lower_text or "weather app" in lower_text or "weather forecast" in lower_text:
            return ProjectContext.WEATHER_SERVICE
        if "database tool" in lower_text or "db tool" in lower_text or "database manager" in lower_text:
            return ProjectContext.DATABASE_TOOL

        return ProjectContext.GENERIC
