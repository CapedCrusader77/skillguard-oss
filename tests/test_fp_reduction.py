import json
from pathlib import Path
from skillguard.models.finding import Finding
from skillguard.core.scoring import calculate_score, evaluate_risk
from skillguard.core.trust_score import calculate_trust_score
from skillguard.analysis.context_analyzer import ContextAnalyzer, ProjectContext
from skillguard.app import aggregate_findings

def test_confidence_system():
    # Verify Finding confidence defaults to HIGH
    finding = Finding(
        id="CMD001",
        severity="HIGH",
        category="COMMAND_EXECUTION",
        file="app.py",
        line=10,
        message="subprocess.Popen detected"
    )
    assert finding.confidence == "HIGH"

def test_scoring_capping():
    # Use HIGH severity Popen calls (CMD001) for capping test
    # (LOW findings are capabilities and excluded from risk score)
    findings = [
        Finding(
            id="CMD001",
            severity="HIGH",
            category="COMMAND_EXECUTION",
            file="app.py",
            line=i,
            message="Popen detected"
        )
        for i in range(1, 51)
    ]
    
    # Base weight for CMD001 is 15.
    # Capped score formula: base_score + max(1, 0.2 * base_score) = 15 + 3 = 18
    score = calculate_score(findings)
    assert score == 18

def test_context_analyzer(tmp_path: Path):
    # Verify self-scan awareness when path contains "SkillGuard"
    fake_skillguard_dir = tmp_path / "my-SkillGuard-repo"
    fake_skillguard_dir.mkdir()
    
    analyzer = ContextAnalyzer()
    context = analyzer.analyze_context(fake_skillguard_dir)
    assert context == ProjectContext.SECURITY_SCANNER

def test_context_aware_exemption(tmp_path: Path):
    fake_skillguard_dir = tmp_path / "SkillGuard"
    fake_skillguard_dir.mkdir()
    
    # Scanned files has FIL001 (open) and CMD001 (subprocess)
    findings = [
        Finding(id="FIL001", severity="LOW", category="FILE_SYSTEM", file="app.py", line=5, message="open() detected"),
        Finding(id="CMD001", severity="HIGH", category="COMMAND_EXECUTION", file="app.py", line=12, message="Popen detected")
    ]
    
    # Calculate score with SkillGuard path context (exempts FIL001)
    score_exempt = calculate_score(findings, fake_skillguard_dir)
    # CMD001 is 15. FIL001 is LOW (ignored). Total = 15.
    assert score_exempt == 15
    
    # Calculate trust score with SkillGuard path context
    trust_report = calculate_trust_score(findings, fake_skillguard_dir)
    # Code Safety: Starts 100. CMD001 is HIGH (-15). Unexpected COMMAND capability (-15). Total = 70.
    assert trust_report.code_safety == 70

def test_finding_aggregation():
    findings = [
        Finding(id="NET101", severity="LOW", category="NETWORK", file="app.js", line=5, message="fetch call detected"),
        Finding(id="NET101", severity="LOW", category="NETWORK", file="app.js", line=10, message="fetch call detected"),
        Finding(id="NET101", severity="LOW", category="NETWORK", file="app.js", line=15, message="fetch call detected"),
        # Different file, should not be aggregated with the above
        Finding(id="NET101", severity="LOW", category="NETWORK", file="worker.js", line=2, message="fetch call detected")
    ]
    
    aggregated = aggregate_findings(findings)
    assert len(aggregated) == 2
    
    # Find aggregated for app.js
    app_f = next(f for f in aggregated if f.file == "app.js")
    assert "fetch call detected (3 occurrences)" in app_f.message
    
    # Find aggregated for worker.js
    worker_f = next(f for f in aggregated if f.file == "worker.js")
    assert "fetch call detected" in worker_f.message
    assert "(" not in worker_f.message
