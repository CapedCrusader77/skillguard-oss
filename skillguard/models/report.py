from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
from skillguard.models.finding import Finding
from skillguard.models.risk import RiskLevel
from skillguard.core.trust_score import TrustScoreReport
from skillguard.analysis.models import EvaluationReport

class PermissionLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"

class PermissionFootprint(BaseModel):
    network_access: PermissionLevel = PermissionLevel.NONE
    filesystem_access: PermissionLevel = PermissionLevel.NONE
    environment_access: PermissionLevel = PermissionLevel.NONE
    database_access: PermissionLevel = PermissionLevel.NONE
    browser_automation: PermissionLevel = PermissionLevel.NONE
    command_execution: PermissionLevel = PermissionLevel.NONE
    container_management: PermissionLevel = PermissionLevel.NONE
    git_operations: PermissionLevel = PermissionLevel.NONE

class ExecutiveSummary(BaseModel):
    verdict: str = Field(..., description="SAFE, CAUTION, or DANGEROUS")
    message: str = Field(..., description="Short explanation sentence")

class RepositoryReport(BaseModel):
    name: str = Field(..., description="Repository directory name")
    path: str = Field(..., description="Absolute path of the repository")
    score: int = Field(..., description="Repository risk score")
    risk: RiskLevel = Field(..., description="Repository risk level")
    trust_score: TrustScoreReport = Field(..., description="Detailed Trust Score breakdown")
    permission_footprint: PermissionFootprint = Field(..., description="Permissions footprint summary")
    findings: List[Finding] = Field(default_factory=list, description="Security findings for this repository")
    evaluation_report: Optional[EvaluationReport] = Field(None, description="Claim vs Behavior Evaluation Report")
    project_type: str = Field("Generic", description="Profiled project type")
    verdict: str = Field(..., description="SAFE, REVIEW RECOMMENDED, HIGH RISK, or DANGEROUS")

class PortfolioSummary(BaseModel):
    total_repositories: int = Field(..., description="Total repositories scanned")
    total_files: int = Field(..., description="Total source files scanned")
    overall_trust_score: int = Field(..., description="Overall average trust score")
    overall_risk_score: int = Field(..., description="Overall maximum/aggregated risk score")
    overall_risk_level: RiskLevel = Field(..., description="Overall risk level")
    verdict: str = Field(..., description="SAFE, REVIEW RECOMMENDED, HIGH RISK, or DANGEROUS")
    message: str = Field(..., description="Summary verdict message")

class Report(BaseModel):
    # Root level fields (for backward compatibility)
    score: int = Field(..., description="Aggregated risk score")
    risk: RiskLevel = Field(..., description="Overall risk level")
    findings: List[Finding] = Field(default_factory=list, description="List of actual high/critical security findings")
    trust_score: Optional[TrustScoreReport] = Field(None, description="Detailed Trust Score breakdown")
    evaluation_report: Optional[EvaluationReport] = Field(None, description="Claim vs Behavior Evaluation Report")
    project_type: str = Field("Generic", description="Profiled project type")
    permission_footprint: PermissionFootprint = Field(default_factory=PermissionFootprint, description="Permissions footprint summary")
    executive_summary: ExecutiveSummary = Field(..., description="Executive summary status")

    # Repository-level risk isolation fields
    repositories: List[RepositoryReport] = Field(default_factory=list, description="Isolated per-repository scan results")
    portfolio_summary: Optional[PortfolioSummary] = Field(None, description="Aggregated summary of all scanned repositories")
