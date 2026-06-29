from enum import Enum
from typing import List, Optional
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
