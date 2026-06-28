from pathlib import Path
from typing import List, Set
from pydantic import BaseModel, Field
from skillguard.models.finding import Finding
from skillguard.analysis.context_analyzer import ContextAnalyzer, ProjectContext
from skillguard.analysis.project_profiler import ProjectProfiler, ProjectType, Capability

class TrustScoreReport(BaseModel):
    overall_score: int = Field(..., description="Overall Trust Score (0-100)")
    code_safety: int = Field(..., description="Code Safety category score")
    supply_chain_safety: int = Field(..., description="Supply Chain Safety category score")
    secrets_hygiene: int = Field(..., description="Secrets Hygiene category score")
    network_risk: int = Field(..., description="Network Risk category score")
    container_security: int = Field(..., description="Container Security category score")
    top_risks: List[str] = Field(default_factory=list, description="Top risks list")
    most_common_behaviors: List[str] = Field(default_factory=list, description="Most common behaviors list")
    reasons: List[str] = Field(default_factory=list, description="Trust explanation reasons (+ / -)")

SEVERITY_DEDUCTIONS = {
    "CRITICAL": 25,
    "HIGH": 15,
}

def calculate_trust_score(findings: List[Finding], repo_path: Path = None) -> TrustScoreReport:
    """
    Calculate Trust Score starting at 100.
    Deductions are only applied for HIGH and CRITICAL findings (actual vulnerabilities)
    and unexpected capabilities for the profiled project type.
    """
    # 1. Determine project context and profile type
    project_context = ProjectContext.GENERIC
    project_type = ProjectType.GENERIC
    
    if repo_path:
        try:
            project_context = ContextAnalyzer().analyze_context(repo_path)
            project_type = ProjectProfiler().profile_project(repo_path)
        except Exception:
            pass

    # Category subscores starting at 100
    scores = {
        "Code Safety": 100,
        "Supply Chain Safety": 100,
        "Secrets Hygiene": 100,
        "Network Risk": 100,
        "Container Security": 100
    }

    # Map finding category to trust score category
    category_map = {
        "COMMAND_EXECUTION": "Code Safety",
        "FILE_SYSTEM": "Code Safety",
        "SUPPLY_CHAIN": "Supply Chain Safety",
        "SECRET_ACCESS": "Secrets Hygiene",
        "NETWORK": "Network Risk",
        "CONTAINER_SECURITY": "Container Security"
    }

    # Only deduct for HIGH and CRITICAL findings
    security_findings = [f for f in findings if f.severity.upper() in {"HIGH", "CRITICAL"}]

    # Self-scan filesystem rule ID exemptions
    filesystem_exempt_ids = {
        "FIL001", "FIL002", "FIL003", "FIL004",  # Python
        "FIL101", "FIL102", "FIL103"              # JS/TS
    }

    # Group findings in the category by ID to apply capped deductions
    category_findings = {}
    for f in security_findings:
        # Relax file rules in self-scan mode
        if project_context in {ProjectContext.SECURITY_SCANNER, ProjectContext.CLI_TOOL} and f.id in filesystem_exempt_ids:
            continue
            
        trust_cat = category_map.get(f.category, "Code Safety")
        if trust_cat not in category_findings:
            category_findings[trust_cat] = {}
        category_findings[trust_cat][f.id] = category_findings[trust_cat].get(f.id, 0) + 1

    # Apply subscore deductions for security findings
    for trust_cat, id_counts in category_findings.items():
        deduction = 0
        for fid, count in id_counts.items():
            severity = next(f.severity for f in findings if f.id == fid)
            base_ded = SEVERITY_DEDUCTIONS.get(severity.upper(), 0)
            
            if count >= 2:
                deduction += base_ded + max(1, int(0.2 * base_ded))
            elif count == 1:
                deduction += base_ded
        scores[trust_cat] -= deduction

    # Evaluate active capabilities from findings & behavior analyzer
    active_capabilities: Set[Capability] = set()
    try:
        from skillguard.analysis.behavior_analyzer import BehaviorAnalyzer
        behavior = BehaviorAnalyzer().analyze_behavior(repo_path or Path("."), findings)
    except Exception:
        behavior = None

    if behavior:
        if behavior.filesystem_access:
            active_capabilities.add(Capability.FILESYSTEM)
        if behavior.network_access:
            active_capabilities.add(Capability.NETWORK)
        if behavior.database_access:
            active_capabilities.add(Capability.DATABASE)
        if behavior.browser_automation:
            active_capabilities.add(Capability.BROWSER)
        if behavior.credential_access:
            active_capabilities.add(Capability.ENVIRONMENT)

    if any(f.category == "COMMAND_EXECUTION" for f in findings):
        active_capabilities.add(Capability.COMMAND)
    if any(f.id.startswith("DKR") for f in findings):
        active_capabilities.add(Capability.CONTAINER)
    if any(f.id.startswith("GHA") for f in findings):
        active_capabilities.add(Capability.GIT)

    # Calculate unexpected capability deductions (15 points each)
    unexpected = ProjectProfiler().get_unexpected_capabilities(project_type, active_capabilities)
    
    # Filesystem unexpected check is skipped in self-scan mode
    if project_context in {ProjectContext.SECURITY_SCANNER, ProjectContext.CLI_TOOL}:
        unexpected.discard(Capability.FILESYSTEM)

    for cap in unexpected:
        # Unexpected code execution or environment access deducts from Code Safety / Secrets Hygiene respectively
        if cap == Capability.COMMAND:
            scores["Code Safety"] -= 15
        elif cap in {Capability.ENVIRONMENT, Capability.DATABASE}:
            scores["Secrets Hygiene"] -= 15
        else:
            scores["Network Risk"] -= 15

    # Cap subscores between 0 and 100
    for cat in scores:
        scores[cat] = max(0, min(100, scores[cat]))

    # Calculate overall average
    overall = int(round(sum(scores.values()) / 5.0))

    # Extract Top Risks (restricted to HIGH/CRITICAL)
    sorted_findings = sorted(
        security_findings, 
        key=lambda x: {"CRITICAL": 4, "HIGH": 3}.get(x.severity.upper(), 0),
        reverse=True
    )
    top_risks = []
    seen_risk_ids = set()
    for f in sorted_findings:
        if len(top_risks) >= 3:
            break
        if f.id not in seen_risk_ids:
            seen_risk_ids.add(f.id)
            top_risks.append(f"[{f.severity.upper()}] {f.message}")
            
    # Include unexpected capabilities as top risks if no actual exploits
    for cap in sorted(list(unexpected)):
        if len(top_risks) >= 3:
            break
        top_risks.append(f"[UNEXPECTED] Undeclared capability: {cap.value}")

    if not top_risks:
        top_risks.append("No significant security risks detected")

    # Extract Most Common Behaviors (grouped by message)
    behavior_counts = {}
    for f in findings:
        behavior_counts[f.message] = behavior_counts.get(f.message, 0) + 1
        
    sorted_behaviors = sorted(behavior_counts.items(), key=lambda x: x[1], reverse=True)
    most_common_behaviors = []
    for msg, count in sorted_behaviors[:3]:
        most_common_behaviors.append(f"{msg} ({count} occurrences)")

    # Generate reasons (+ / -)
    reasons = []
    has_cmd = any(f.id in {"CMD001", "CMD002", "CMD003", "CMD004", "CMD005", "CMD101", "CMD102", "CMD103"} for f in findings)
    has_secrets = any(f.id in {"SEC101", "GHA003"} for f in findings)
    has_docker_crit = any(f.id in {"DKR003"} for f in findings)
    has_workflow_crit = any(f.id in {"GHA001"} for f in findings)

    if not has_cmd:
        reasons.append("+ No dangerous command execution")
    if not has_secrets:
        reasons.append("+ No hardcoded secrets")
    if not has_docker_crit:
        reasons.append("+ No suspicious Dockerfiles")
    if not has_workflow_crit:
        reasons.append("+ Clean workflow configurations")

    for cap in sorted(list(unexpected)):
        reasons.append(f"- Unexpected capability: {cap.value}")

    return TrustScoreReport(
        overall_score=overall,
        code_safety=scores["Code Safety"],
        supply_chain_safety=scores["Supply Chain Safety"],
        secrets_hygiene=scores["Secrets Hygiene"],
        network_risk=scores["Network Risk"],
        container_security=scores["Container Security"],
        top_risks=top_risks,
        most_common_behaviors=most_common_behaviors,
        reasons=reasons
    )
