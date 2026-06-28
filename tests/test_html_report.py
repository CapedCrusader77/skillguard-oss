from pathlib import Path
from skillguard.models.report import Report, PermissionLevel, PermissionFootprint, ExecutiveSummary
from skillguard.models.finding import Finding
from skillguard.models.risk import RiskLevel
from skillguard.core.trust_score import TrustScoreReport
from skillguard.analysis.models import EvaluationReport, BehaviorProfile, ClaimedCategory
from skillguard.reports.html_report import write_html_report

def test_write_html_report(tmp_path: Path):
    report_file = tmp_path / "report.html"
    
    # Mock data
    findings = [
        Finding(id="CMD001", severity="HIGH", category="COMMAND_EXECUTION", file="app.py", line=10, message="subprocess.Popen detected"),
        Finding(id="SEC101", severity="CRITICAL", category="SECRET_ACCESS", file=".env", line=2, message="Hardcoded OpenAI key detected")
    ]
    
    eval_report = EvaluationReport(
        claimed_purpose="Weather forecaster MCP utility",
        claimed_categories=[ClaimedCategory.WEATHER],
        observed_behavior=BehaviorProfile(network_access=True, filesystem_access=True),
        mismatches=["Undeclared filesystem access"],
        trust_score=65,
        verdict="Behavior partially exceeds declared functionality"
    )
    
    footprint = PermissionFootprint(
        network_access=PermissionLevel.HIGH,
        filesystem_access=PermissionLevel.MEDIUM,
        environment_access=PermissionLevel.LOW
    )
    
    summary = ExecutiveSummary(
        verdict="CAUTION",
        message="Uses command execution for expected functionality."
    )
    
    report = Report(
        score=40,
        risk=RiskLevel.MEDIUM,
        findings=findings,
        evaluation_report=eval_report,
        project_type="CLI Tool",
        permission_footprint=footprint,
        executive_summary=summary
    )
    
    trust_report = TrustScoreReport(
        overall_score=75,
        code_safety=80,
        supply_chain_safety=100,
        secrets_hygiene=75,
        network_risk=100,
        container_security=100,
        top_risks=["[HIGH] subprocess.Popen detected"],
        most_common_behaviors=["subprocess.Popen detected (1 occurrences)"],
        reasons=["+ No hardcoded secrets"]
    )

    path = write_html_report(report, trust_report, str(report_file))

    assert path.exists()
    html_content = path.read_text(encoding="utf-8")
    
    assert "SkillGuard Report" in html_content
    assert "75" in html_content  # Overall score
    assert "MEDIUM Risk" in html_content
    assert "subprocess.Popen detected" in html_content
    assert "Hardcoded OpenAI key detected" in html_content
    assert "gauge-fill" in html_content
    
    # Check claim vs behavior alignment output
    assert "Claim vs Behavior Alignment" in html_content
    assert "Weather forecaster MCP utility" in html_content
    assert "Undeclared filesystem access" in html_content
    assert "Behavior partially exceeds declared functionality" in html_content
