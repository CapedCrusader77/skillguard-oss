"""Claim extraction for the static and runtime verification pipelines."""

import ast
import json
import re
import tomllib
from pathlib import Path
from typing import Any, Iterable, List, Set

from skillguard.analysis.models import (
    AccessMode,
    ClaimEvidence,
    ClaimProfile,
    ClaimState,
    ClaimedCategory,
    FunctionClaim,
    ManifestClaim,
    ProjectClaims,
    ResourceClaim,
)

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

_READ_RE = re.compile(r"\b(read|reads|reading|view|views|list|lists|inspect|lookup|query|queries)\b", re.I)
_WRITE_RE = re.compile(r"\b(write|writes|writing|create|creates|edit|update|modify|save|saves|send|delete|remove)\b", re.I)
_DOMAIN_RE = re.compile(r"(?:https?://)?([a-z0-9][a-z0-9.-]+\.[a-z]{2,})(?::(\d+))?", re.I)
_PATH_RE = re.compile(r"(?<![\w])(?:~|/|\.\.?/)[\w./${}*?\-]+")


class BaseClaimExtractor:
    def extract_claims(self, repo_path: Path) -> ProjectClaims:
        raise NotImplementedError()

    def extract_profile(self, repo_path: Path) -> ClaimProfile:
        raise NotImplementedError()


class RuleBasedClaimExtractor(BaseClaimExtractor):
    """Extract claims from documentation, manifests, and Python declarations."""

    def extract_claims(self, repo_path: Path) -> ProjectClaims:
        profile = self.extract_profile(repo_path)
        return ProjectClaims(claimed_purpose=profile.claimed_purpose, categories=profile.categories)

    def extract_profile(self, repo_path: Path) -> ClaimProfile:
        target = Path(repo_path).resolve()
        root_dir = target.parent if target.is_file() else target
        text_sources: list[tuple[str, str, str]] = []
        manifests: list[ManifestClaim] = []
        evidence: list[ClaimEvidence] = []
        warnings: list[str] = []

        def add_text(source_type: str, path: Path, content: str) -> None:
            if content.strip():
                text_sources.append((source_type, str(path), content))

        package_json = root_dir / "package.json"
        if package_json.exists():
            try:
                data = json.loads(package_json.read_text(encoding="utf-8", errors="ignore"))
                manifests.append(self._manifest_claim(package_json, "package.json", data))
                if data.get("description"):
                    add_text("manifest", package_json, str(data["description"]))
            except Exception as exc:
                warnings.append(f"Could not parse {package_json.name}: {exc}")

        pyproject = root_dir / "pyproject.toml"
        if pyproject.exists():
            try:
                raw = pyproject.read_text(encoding="utf-8", errors="ignore")
                data = tomllib.loads(raw)
                manifests.append(self._manifest_claim(pyproject, "pyproject.toml", data))
                desc = data.get("project", {}).get("description") or data.get("description")
                if desc:
                    add_text("manifest", pyproject, str(desc))
            except Exception as exc:
                warnings.append(f"Could not parse {pyproject.name}: {exc}")

        pubspec = root_dir / "pubspec.yaml"
        if pubspec.exists():
            try:
                raw = pubspec.read_text(encoding="utf-8", errors="ignore")
                manifests.append(self._manifest_claim(pubspec, "pubspec.yaml", self._simple_yaml_fields(raw)))
                match = re.search(r"^description:\s*(.+)$", raw, re.MULTILINE)
                if match:
                    add_text("manifest", pubspec, match.group(1).strip().strip("'\""))
            except Exception as exc:
                warnings.append(f"Could not parse {pubspec.name}: {exc}")

        readme = next((p for p in (root_dir / "README.md", root_dir / "README.txt", root_dir / "readme.md", root_dir / "readme.txt") if p.exists()), None)
        if readme:
            try:
                add_text("README", readme, readme.read_text(encoding="utf-8", errors="ignore"))
            except Exception as exc:
                warnings.append(f"Could not read {readme.name}: {exc}")

        docs_dir = root_dir / "docs"
        if docs_dir.is_dir():
            for path in docs_dir.rglob("*"):
                if path.is_file() and path.suffix.lower() in {".md", ".txt"}:
                    try:
                        add_text("docs", path, path.read_text(encoding="utf-8", errors="ignore"))
                    except Exception as exc:
                        warnings.append(f"Could not read {path}: {exc}")

        functions: list[FunctionClaim] = []
        imports: set[str] = set()
        for path in self._python_files(root_dir, target):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=str(path))
            except (OSError, SyntaxError) as exc:
                warnings.append(f"Could not parse {path}: {exc}")
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module)
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    docstring = ast.get_docstring(node)
                    item = ClaimEvidence(
                        source_type="docstring" if docstring else "function_name",
                        source_path=str(path), line=node.lineno,
                        excerpt=docstring or node.name,
                        confidence="high" if docstring else "medium",
                    )
                    functions.append(FunctionClaim(
                        name=node.name, qualified_name=node.name, docstring=docstring,
                        source_path=str(path), line=node.lineno, evidence=[item],
                    ))
                    evidence.append(item)
                    if docstring:
                        add_text("docstring", path, docstring)

        combined = " ".join(text for _, _, text in text_sources)
        categories = self._categories(combined) or [ClaimedCategory.OTHER]
        profile = ClaimProfile(
            target=str(target), claimed_purpose=self._purpose(text_sources) or "AI Agent Tool / Plugin",
            categories=categories, functions=functions, manifests=manifests,
            imports=sorted(imports), evidence=evidence, extraction_warnings=warnings,
        )
        for source_type, source_path, text in text_sources:
            self._apply_text_claims(profile, source_type, source_path, text)
        self._apply_manifest_claims(profile, manifests)
        return profile

    @staticmethod
    def _python_files(root_dir: Path, target: Path) -> Iterable[Path]:
        if target.is_file() and target.suffix.lower() == ".py":
            return [target]
        return (p for p in root_dir.rglob("*.py") if ".git" not in p.parts and "__pycache__" not in p.parts)

    @staticmethod
    def _purpose(sources: list[tuple[str, str, str]]) -> str:
        for source_type, _, content in sources:
            if source_type == "manifest" and content.strip():
                return content.strip()
        for _, _, content in sources:
            for line in content.splitlines():
                clean = line.strip()
                if clean and not clean.startswith(("#", "=", "-", "```")):
                    return clean
        return ""

    @staticmethod
    def _categories(text: str) -> list[ClaimedCategory]:
        lower = text.lower()
        return sorted({category for category, words in CATEGORY_KEYWORDS.items() if any(word in lower for word in words)}, key=lambda c: c.value)

    @staticmethod
    def _manifest_claim(path: Path, format_name: str, data: dict[str, Any]) -> ManifestClaim:
        permissions: list[str] = []

        def walk(value: Any, key: str = "") -> None:
            if isinstance(value, dict):
                for child_key, child_value in value.items():
                    if any(token in child_key.lower() for token in ("permission", "capability", "access", "allow")):
                        permissions.append(f"{child_key}={child_value}")
                    walk(child_value, child_key)
            elif isinstance(value, list) and any(token in key.lower() for token in ("permission", "capability", "access", "allow")):
                permissions.extend(str(item) for item in value)

        walk(data)
        return ManifestClaim(path=str(path), format=format_name, fields=data, declared_permissions=permissions)

    @staticmethod
    def _simple_yaml_fields(raw: str) -> dict[str, Any]:
        fields: dict[str, Any] = {}
        for line in raw.splitlines():
            match = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
            if match:
                fields[match.group(1)] = match.group(2).strip().strip("'\"")
        return fields

    def _apply_text_claims(self, profile: ClaimProfile, source_type: str, source_path: str, text: str) -> None:
        evidence = ClaimEvidence(source_type=source_type, source_path=source_path, excerpt=text[:300], confidence="medium")
        lower = text.lower()
        if any(word in lower for word in ("file", "filesystem", "directory", "folder", "disk")):
            paths = [path for path in _PATH_RE.findall(text) if not path.startswith("//")]
            self._merge_claim(profile.filesystem, self._modes(text, AccessMode.READ, AccessMode.WRITE), paths, evidence)
        if any(word in lower for word in ("network", "http", "https", "api", "web", "internet", "domain")):
            matches = list(_DOMAIN_RE.finditer(text))
            domains = [m.group(1).lower() for m in matches if m.group(1).lower().rsplit(".", 1)[-1] not in {"json", "yaml", "yml", "toml", "txt", "md", "py"}]
            self._merge_claim(profile.network, [AccessMode.CONNECT], domains, evidence,
                              ports=[int(m.group(2)) for m in matches if m.group(2)], protocols=self._protocols(text))
        if any(word in lower for word in ("subprocess", "shell", "command", "execute", "run a process")):
            self._merge_claim(profile.subprocess, [AccessMode.EXECUTE], [], evidence)
        if any(word in lower for word in ("environment variable", "credential", "secret", "token", "device", "system resource")):
            self._merge_claim(profile.system_resources, [AccessMode.ACCESS], re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", text), evidence)

    def _apply_manifest_claims(self, profile: ClaimProfile, manifests: list[ManifestClaim]) -> None:
        for manifest in manifests:
            for permission in manifest.declared_permissions:
                text = permission.lower()
                evidence = ClaimEvidence(source_type="manifest", source_path=manifest.path, excerpt=permission, confidence="high")
                if any(token in text for token in ("file", "filesystem", "disk")):
                    modes = []
                    if "read" in text:
                        modes.append(AccessMode.READ)
                    if any(token in text for token in ("write", "modify", "delete")):
                        modes.append(AccessMode.WRITE)
                    self._merge_claim(profile.filesystem, modes or [AccessMode.UNKNOWN], [], evidence)
                if any(token in text for token in ("network", "internet", "http", "socket")):
                    self._merge_claim(profile.network, [AccessMode.CONNECT], [], evidence)
                if any(token in text for token in ("exec", "shell", "command", "process")):
                    self._merge_claim(profile.subprocess, [AccessMode.EXECUTE], [], evidence)
                if any(token in text for token in ("env", "credential", "secret", "token")):
                    self._merge_claim(profile.system_resources, [AccessMode.ACCESS], [], evidence)

    @staticmethod
    def _modes(text: str, read_mode: AccessMode, write_mode: AccessMode) -> list[AccessMode]:
        modes: list[AccessMode] = []
        if _READ_RE.search(text):
            modes.append(read_mode)
        if _WRITE_RE.search(text):
            modes.append(write_mode)
        return modes or [AccessMode.UNKNOWN]

    @staticmethod
    def _protocols(text: str) -> list[str]:
        lower = text.lower()
        return [protocol for protocol in ("http", "https", "tcp", "udp", "smtp", "ssh") if protocol in lower]

    @staticmethod
    def _merge_claim(claim: ResourceClaim, modes: list[AccessMode], resources: list[str], evidence: ClaimEvidence, *, ports: list[int] | None = None, protocols: list[str] | None = None) -> None:
        if claim.evidence and set(claim.modes) and set(modes) and set(claim.modes) != set(modes):
            claim.state = ClaimState.CONFLICTING
        elif claim.state == ClaimState.NOT_DECLARED:
            claim.state = ClaimState.DECLARED
        if AccessMode.UNKNOWN in modes:
            claim.state = ClaimState.UNKNOWN
        if any(item.lower() in {"*", "any", "all"} for item in resources):
            claim.state = ClaimState.UNRESTRICTED
        claim.modes = sorted(set(claim.modes + modes), key=lambda mode: mode.value)
        claim.resources = sorted(set(claim.resources + resources))
        claim.ports = sorted(set(claim.ports + (ports or [])))
        claim.protocols = sorted(set(claim.protocols + (protocols or [])))
        claim.evidence.append(evidence)
