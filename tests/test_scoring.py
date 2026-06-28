from skillguard.models.finding import Finding
from skillguard.models.risk import RiskLevel, get_risk_level
from skillguard.core.scoring import calculate_score, evaluate_risk

def test_risk_level_boundaries():
    # 0-20 LOW
    assert get_risk_level(0) == RiskLevel.LOW
    assert get_risk_level(15) == RiskLevel.LOW
    assert get_risk_level(20) == RiskLevel.LOW
    
    # 21-50 MEDIUM
    assert get_risk_level(21) == RiskLevel.MEDIUM
    assert get_risk_level(35) == RiskLevel.MEDIUM
    assert get_risk_level(50) == RiskLevel.MEDIUM
    
    # 51-80 HIGH
    assert get_risk_level(51) == RiskLevel.HIGH
    assert get_risk_level(70) == RiskLevel.HIGH
    assert get_risk_level(80) == RiskLevel.HIGH
    
    # 81+ CRITICAL
    assert get_risk_level(81) == RiskLevel.CRITICAL
    assert get_risk_level(120) == RiskLevel.CRITICAL

def test_calculate_score():
    findings = [
        Finding(
            id="CMD001",  # subprocess.Popen (15)
            severity="HIGH",
            category="COMMAND_EXECUTION",
            file="file.py",
            line=10,
            message="subprocess.Popen"
        ),
        Finding(
            id="CMD005",  # shell=True (15)
            severity="HIGH",
            category="COMMAND_EXECUTION",
            file="file.py",
            line=10,
            message="shell=True"
        ),
        Finding(
            id="NET001",  # requests.post (5)
            severity="MEDIUM",
            category="NETWORK",
            file="file.py",
            line=15,
            message="requests.post"
        ),
        Finding(
            id="FIL001",  # open() (1)
            severity="LOW",
            category="FILE_SYSTEM",
            file="file.py",
            line=20,
            message="open()"
        ),
    ]
    # Total score: 15 + 15 = 30 (LOW/MEDIUM are capabilities and excluded)
    assert calculate_score(findings) == 30
    
    score, risk_level = evaluate_risk(findings)
    assert score == 30
    assert risk_level == RiskLevel.MEDIUM
