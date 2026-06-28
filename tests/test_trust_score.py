from skillguard.models.finding import Finding
from skillguard.core.trust_score import calculate_trust_score

def test_trust_score_calculation():
    # Setup findings
    findings = [
        # Code Safety deductions
        Finding(id="CMD001", severity="HIGH", category="COMMAND_EXECUTION", file="f.py", line=1, message="Popen"),  # -15
        Finding(id="FIL001", severity="LOW", category="FILE_SYSTEM", file="f.py", line=2, message="open"),          # -0 (ignored)
        
        # Supply Chain deductions
        Finding(id="DEP001", severity="HIGH", category="SUPPLY_CHAIN", file="r.txt", line=1, message="typo"),        # -15
        Finding(id="GHA002", severity="MEDIUM", category="SUPPLY_CHAIN", file="w.yml", line=1, message="unpinned"),  # -0 (ignored)
        Finding(id="DEP002", severity="LOW", category="SUPPLY_CHAIN", file="r.txt", line=2, message="dup"),         # -0 (ignored)
        Finding(id="DEP002", severity="LOW", category="SUPPLY_CHAIN", file="r.txt", line=3, message="dup"),
        Finding(id="DEP002", severity="LOW", category="SUPPLY_CHAIN", file="r.txt", line=4, message="dup"),
        Finding(id="DEP002", severity="LOW", category="SUPPLY_CHAIN", file="r.txt", line=5, message="dup"),
        Finding(id="DEP002", severity="LOW", category="SUPPLY_CHAIN", file="r.txt", line=6, message="dup"),
        
        # Secrets Hygiene deductions
        # (No findings -> should be 100)
        
        # Network Risk deductions
        Finding(id="NET001", severity="MEDIUM", category="NETWORK", file="f.py", line=3, message="requests.post"),  # -0 (ignored)
        Finding(id="NET201", severity="LOW", category="NETWORK", file="f.py", line=3, message="External Dest"),      # -0 (ignored)
        Finding(id="NET201", severity="LOW", category="NETWORK", file="f.py", line=4, message="External Dest"),
        Finding(id="NET201", severity="LOW", category="NETWORK", file="f.py", line=5, message="External Dest"),
        Finding(id="NET201", severity="LOW", category="NETWORK", file="f.py", line=6, message="External Dest"),
        Finding(id="NET201", severity="LOW", category="NETWORK", file="f.py", line=7, message="External Dest"),
        Finding(id="NET201", severity="LOW", category="NETWORK", file="f.py", line=8, message="External Dest"),
        Finding(id="NET201", severity="LOW", category="NETWORK", file="f.py", line=9, message="External Dest"),
        Finding(id="NET201", severity="LOW", category="NETWORK", file="f.py", line=10, message="External Dest"),
        Finding(id="NET201", severity="LOW", category="NETWORK", file="f.py", line=11, message="External Dest"),
        
        # Container Security deductions
        Finding(id="DKR003", severity="CRITICAL", category="CONTAINER_SECURITY", file="D", line=1, message="curl"),  # -25
        Finding(id="DKR005", severity="HIGH", category="CONTAINER_SECURITY", file="D", line=2, message="chmod"),    # -15
        Finding(id="DKR001", severity="HIGH", category="CONTAINER_SECURITY", file="D", line=3, message="root"),     # -15
        Finding(id="DKR002", severity="MEDIUM", category="CONTAINER_SECURITY", file="D", line=4, message="no user"),# -0 (ignored)
        Finding(id="DKR006", severity="HIGH", category="CONTAINER_SECURITY", file="D", line=5, message="priv"),     # -15 (grouped)
        Finding(id="DKR006", severity="HIGH", category="CONTAINER_SECURITY", file="D", line=6, message="priv"),
    ]

    report = calculate_trust_score(findings)

    # Math under Phase 5:
    # 1. Code Safety: 100 - 15 (CMD001) - 15 (unexpected COMMAND) = 70%
    # 2. Supply Chain Safety: 100 - 15 (DEP001) = 85%
    # 3. Secrets Hygiene: 100 - 15 (unexpected DATABASE) = 85%
    # 4. Network Risk: 100 - 45 (unexpected CONTAINER, GIT, BROWSER) = 55%
    # 5. Container Security: 100 - (25 + 15 + 15 + 18) = 27%
    
    assert report.code_safety == 70
    assert report.supply_chain_safety == 85
    assert report.secrets_hygiene == 85
    assert report.network_risk == 55
    assert report.container_security == 27

    # Overall: average of 70, 85, 85, 55, 27 = 322 / 5 = 64.4 -> 64%
    assert report.overall_score == 64
