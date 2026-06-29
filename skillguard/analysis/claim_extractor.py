import os
import json
import re
from pathlib import Path
from typing import List, Set
from skillguard.analysis.models import ProjectClaims, ClaimedCategory

CATEGORY_KEYWORDS = {
    ClaimedCategory.WEATHER: ["weather", "forecast", "meteorology", "temperature", "rain", "snow", "climate"],
    ClaimedCategory.FILESYSTEM: ["filesystem", "file system", "folder", "directory", "local file", "read file", "write file", "chmod", "disk"],
    ClaimedCategory.DATABASE: ["database", "sqlite", "postgres", "mysql", "mongodb", "db ", "sql ", "prisma", "orm", "nosql", "redis"],
    ClaimedCategory.EMAIL: ["email", "mail", "smtp", "imap", "nodemailer", "sendgrid", "postfix"],
    ClaimedCategory.GITHUB: ["github", "octokit", "pull request", "git repo"],
    ClaimedCategory.SLACK: ["slack", "slackbot"],
    ClaimedCategory.DISCORD: ["discord", "discordbot"],
    ClaimedCategory.SEARCH: ["search engine", "google search", "tavily", "brave search", "duckduckgo", "bing search"],
    ClaimedCategory.WEB_SCRAPING: ["web scraping", "scrape", "scraping", "beautifulsoup", "bs4", "scrapy", "crawler"],
    ClaimedCategory.BROWSER_AUTOMATION: ["browser automation", "playwright", "puppeteer", "selenium", "webdriver", "browser-use"],
    ClaimedCategory.CODE_GENERATION: ["code generation", "compiler", "codegen", "transpiler", "refactoring"],
    ClaimedCategory.AGENT_FRAMEWORK: ["agent framework", "langchain", "langgraph", "crewai", "autogen", "swarm"],
    ClaimedCategory.KNOWLEDGE_BASE: ["knowledge base", "rag ", "vector store", "chromadb", "pinecone", "qdrant"],
    ClaimedCategory.MONITORING: ["monitoring", "prometheus", "grafana", "sentry", "otel", "opentelemetry"],
    ClaimedCategory.ANALYTICS: ["analytics", "mixpanel", "posthog", "segment", "amplitude"],
}

class BaseClaimExtractor:
    def extract_claims(self, repo_path: Path) -> ProjectClaims:
        raise NotImplementedError()

class RuleBasedClaimExtractor(BaseClaimExtractor):
    def extract_claims(self, repo_path: Path) -> ProjectClaims:
        if repo_path.is_file():
            root_dir = repo_path.parent
        else:
            root_dir = repo_path

        purpose = ""
        combined_text = ""

        # 1. Try reading package.json
        pkg_json = root_dir / "package.json"
        if pkg_json.exists():
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8", errors="ignore"))
                desc = data.get("description", "")
                if desc:
                    purpose = desc
                    combined_text += " " + desc
            except Exception:
                pass

        # 2. Try reading pyproject.toml
        pyproject = root_dir / "pyproject.toml"
        if pyproject.exists():
            try:
                content = pyproject.read_text(encoding="utf-8", errors="ignore")
                desc_match = re.search(r'description\s*=\s*["\']([^"\']+)["\']', content)
                if desc_match:
                    desc = desc_match.group(1)
                    if not purpose:
                        purpose = desc
                    combined_text += " " + desc
            except Exception:
                pass

        # 2.5 Try reading pubspec.yaml
        pubspec = root_dir / "pubspec.yaml"
        if pubspec.exists():
            try:
                content = pubspec.read_text(encoding="utf-8", errors="ignore")
                desc_match = re.search(r'^description\s*:\s*(.+)$', content, re.MULTILINE)
                if desc_match:
                    desc = desc_match.group(1).strip()
                    desc = desc.strip('\'"')
                    if not purpose:
                        purpose = desc
                    combined_text += " " + desc
            except Exception:
                pass

        # 3. Try reading README.md or README.txt
        readme_files = [root_dir / "README.md", root_dir / "README.txt", root_dir / "readme.md", root_dir / "readme.txt"]
        readme_content = ""
        for rf in readme_files:
            if rf.exists():
                try:
                    readme_content = rf.read_text(encoding="utf-8", errors="ignore")
                    combined_text += " " + readme_content
                    
                    if not purpose:
                        lines = readme_content.splitlines()
                        for line in lines:
                            clean = line.strip()
                            if clean and not clean.startswith("#") and not clean.startswith("="):
                                purpose = clean
                                break
                    break
                except Exception:
                    pass

        # 4. Check docs/ directory
        docs_dir = root_dir / "docs"
        if docs_dir.exists() and docs_dir.is_dir():
            for root, _, files in os.walk(docs_dir):
                for f in files:
                    if f.endswith((".md", ".txt")):
                        try:
                            combined_text += " " + Path(root).joinpath(f).read_text(encoding="utf-8", errors="ignore")
                        except Exception:
                            pass

        if not purpose:
            purpose = "AI Agent Tool / Plugin"

        # Apply keyword matching to extract categories
        categories: Set[ClaimedCategory] = set()
        lower_text = combined_text.lower()

        for category, keywords in CATEGORY_KEYWORDS.items():
            for kw in keywords:
                if kw in lower_text:
                    categories.add(category)
                    break

        if not categories:
            categories.add(ClaimedCategory.OTHER)

        return ProjectClaims(
            claimed_purpose=purpose.strip(),
            categories=sorted(list(categories), key=lambda x: x.value)
        )
