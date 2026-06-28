from typing import List, Set
from skillguard.analysis.models import EvaluationReport, ProjectClaims, BehaviorProfile, ClaimedCategory

ALLOWED_BEHAVIORS = {
    ClaimedCategory.WEATHER: {"network_access"},
    ClaimedCategory.FILESYSTEM: {"filesystem_access"},
    ClaimedCategory.DATABASE: {"database_access", "filesystem_access"},
    ClaimedCategory.EMAIL: {"network_access", "email_access"},
    ClaimedCategory.GITHUB: {"network_access"},
    ClaimedCategory.SLACK: {"network_access"},
    ClaimedCategory.DISCORD: {"network_access"},
    ClaimedCategory.SEARCH: {"network_access"},
    ClaimedCategory.WEB_SCRAPING: {"network_access"},
    ClaimedCategory.BROWSER_AUTOMATION: {"network_access", "browser_automation"},
    ClaimedCategory.CODE_GENERATION: {"filesystem_access"},
    ClaimedCategory.AGENT_FRAMEWORK: {"network_access", "filesystem_access", "credential_access"},
    ClaimedCategory.KNOWLEDGE_BASE: {"network_access", "filesystem_access", "database_access"},
    ClaimedCategory.MONITORING: {"network_access", "filesystem_access"},
    ClaimedCategory.ANALYTICS: {"network_access"},
    ClaimedCategory.OTHER: {"filesystem_access", "network_access"},
}

class TrustEvaluator:
    def evaluate(self, claims: ProjectClaims, behavior: BehaviorProfile) -> EvaluationReport:
        expected: Set[str] = set()
        for cat in claims.categories:
            allowed = ALLOWED_BEHAVIORS.get(cat, set())
            expected.update(allowed)

        mismatches: List[str] = []
        deductions = 0

        # Check mismatches
        if behavior.filesystem_access and "filesystem_access" not in expected:
            mismatches.append("Undeclared filesystem access")
            deductions += 30

        if behavior.credential_access and "credential_access" not in expected:
            mismatches.append("Undeclared credential access")
            deductions += 30

        if behavior.browser_automation and "browser_automation" not in expected:
            mismatches.append("Undeclared browser automation")
            deductions += 20

        if behavior.database_access and "database_access" not in expected:
            mismatches.append("Undeclared database usage")
            deductions += 20

        if behavior.email_access and "email_access" not in expected:
            mismatches.append("Undeclared email usage")
            deductions += 20

        if behavior.network_access and "network_access" not in expected:
            mismatches.append("Undeclared network access")
            deductions += 20

        # Calculate score from base 95
        trust_score = max(0, 95 - deductions)

        # Verdict assignment
        if trust_score < 50:
            verdict = "Behavior exceeds declared functionality"
        elif trust_score < 80:
            verdict = "Behavior partially exceeds declared functionality"
        else:
            verdict = "Behavior matches declared purpose"

        return EvaluationReport(
            claimed_purpose=claims.claimed_purpose,
            claimed_categories=claims.categories,
            observed_behavior=behavior,
            mismatches=mismatches,
            trust_score=trust_score,
            verdict=verdict
        )
