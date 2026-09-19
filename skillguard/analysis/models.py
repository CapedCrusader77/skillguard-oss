from enum import Enum
from typing import Any, List, Optional
from pydantic import BaseModel, Field

class ClaimedCategory(str, Enum):
    WEATHER = "Weather"
    FILESYSTEM = "Filesystem"
    DATABASE = "Database"
    EMAIL = "Email"
    GITHUB = "GitHub"
    SLACK = "Slack"
    DISCORD = "Discord"
    SEARCH = "Search"
    WEB_SCRAPING = "Web Scraping"
    BROWSER_AUTOMATION = "Browser Automation"
    CODE_GENERATION = "Code Generation"
    AGENT_FRAMEWORK = "Agent Framework"
    KNOWLEDGE_BASE = "Knowledge Base"
    MONITORING = "Monitoring"
    ANALYTICS = "Analytics"
    OTHER = "Other"

class ProjectClaims(BaseModel):
    claimed_purpose: str = Field(..., description="The main description or purpose of the project")
    categories: List[ClaimedCategory] = Field(default_factory=list, description="Extracted category classifications")

class BehaviorProfile(BaseModel):
    filesystem_access: bool = Field(False, description="Project reads/writes to local files or walks directory structures")
    network_access: bool = Field(False, description="Project performs outgoing http/https or socket requests")
    database_access: bool = Field(False, description="Project interacts with relational/embedded database modules")
    email_access: bool = Field(False, description="Project communicates with smtp or email interfaces")
    browser_automation: bool = Field(False, description="Project executes automated web browsers (playwright, puppeteer, selenium, etc.)")
    credential_access: bool = Field(False, description="Project fetches API tokens, process.env variables, or displays API credentials")
    command_execution: bool = Field(False, description="Project executes shell or system commands")
    environment_access: bool = Field(False, description="Project accesses environment variables or credentials")


class ClaimState(str, Enum):
    """How explicitly a resource capability is described by the tool."""

    NOT_DECLARED = "not_declared"
    DECLARED = "declared"
    DENIED = "denied"
    UNKNOWN = "unknown"
    UNRESTRICTED = "unrestricted"
    CONFLICTING = "conflicting"


class AccessMode(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    CONNECT = "connect"
    LISTEN = "listen"
    EXECUTE = "execute"
    ACCESS = "access"
    UNKNOWN = "unknown"


class ClaimEvidence(BaseModel):
    """Source provenance for a normalized claim."""

    source_type: str = Field(..., description="docstring, README, manifest, function_name, or import")
    source_path: str
    line: Optional[int] = None
    excerpt: str = ""
    confidence: str = "medium"


class ResourceClaim(BaseModel):
    """A normalized claim for one resource family.

    `not_declared`, `unknown`, and `unrestricted` are deliberately distinct;
    extraction must never turn missing or ambiguous documentation into an
    implicit allow or deny.
    """

    state: ClaimState = ClaimState.NOT_DECLARED
    modes: List[AccessMode] = Field(default_factory=list)
    resources: List[str] = Field(default_factory=list)
    ports: List[int] = Field(default_factory=list)
    protocols: List[str] = Field(default_factory=list)
    evidence: List[ClaimEvidence] = Field(default_factory=list)


class FunctionClaim(BaseModel):
    name: str
    qualified_name: Optional[str] = None
    docstring: Optional[str] = None
    source_path: str
    line: int
    evidence: List[ClaimEvidence] = Field(default_factory=list)


class ManifestClaim(BaseModel):
    path: str
    format: str
    fields: dict[str, Any] = Field(default_factory=dict)
    declared_permissions: List[str] = Field(default_factory=list)
    evidence: List[ClaimEvidence] = Field(default_factory=list)


class ClaimProfile(BaseModel):
    """Structured, provenance-preserving claims extracted before execution."""

    schema_version: str = "1.0"
    target: str
    claimed_purpose: str = "AI Agent Tool / Plugin"
    categories: List[ClaimedCategory] = Field(default_factory=list)
    functions: List[FunctionClaim] = Field(default_factory=list)
    manifests: List[ManifestClaim] = Field(default_factory=list)
    imports: List[str] = Field(default_factory=list)
    filesystem: ResourceClaim = Field(default_factory=ResourceClaim)
    network: ResourceClaim = Field(default_factory=ResourceClaim)
    subprocess: ResourceClaim = Field(default_factory=ResourceClaim)
    system_resources: ResourceClaim = Field(default_factory=ResourceClaim)
    evidence: List[ClaimEvidence] = Field(default_factory=list)
    extraction_warnings: List[str] = Field(default_factory=list)

class EvaluationReport(BaseModel):
    claimed_purpose: str
    claimed_categories: List[ClaimedCategory]
    observed_behavior: BehaviorProfile
    mismatches: List[str] = Field(default_factory=list, description="Warnings or mismatch findings messages")
    trust_score: int = Field(..., ge=0, le=100)
    verdict: str
    ai_assessment: Optional[List[str]] = Field(None, description="AI-generated assessment comments")
    ai_trust_impact: Optional[int] = Field(None, description="AI-generated trust impact score deduction")
    ai_verdict: Optional[str] = Field(None, description="AI-generated verdict")
