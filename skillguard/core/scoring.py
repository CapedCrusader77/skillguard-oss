from pathlib import Path
from typing import List
from skillguard.models.finding import Finding
from skillguard.models.risk import RiskLevel, get_risk_level
from skillguard.analysis.context_analyzer import ContextAnalyzer, ProjectContext

# Direct mapping from finding ID to its risk score weight based on the remapped severities
ID_SCORES = {
    # Python AST Scanners (LOW/MEDIUM/HIGH/CRITICAL)
    "CMD001": 15,  # subprocess.Popen (HIGH)
    "CMD002": 15,  # subprocess.run (HIGH)
    "CMD003": 15,  # subprocess.call (HIGH)
    "CMD004": 15,  # os.system (HIGH)
    "CMD005": 15,  # shell=True (HIGH)
    
    "NET001": 5,   # requests.post (MEDIUM)
    "NET002": 1,   # requests.get (LOW)
    "NET003": 5,   # requests.put (MEDIUM)
    "NET004": 5,   # requests.delete (MEDIUM)
    "NET005": 5,   # httpx (MEDIUM)
    "NET006": 1,   # urllib (LOW)
    "NET007": 5,   # socket (MEDIUM)
    
    "FIL001": 1,   # open() (LOW)
    "FIL002": 1,   # pathlib.Path (LOW)
    "FIL003": 5,   # os.walk (MEDIUM)
    "FIL004": 1,   # glob.glob (LOW)
    
    "SEC001": 1,   # os.getenv (LOW)
    "SEC002": 1,   # os.environ (LOW)

    # JavaScript / TypeScript AST Scanners
    "CMD101": 15,  # child_process.exec (HIGH)
    "CMD102": 15,  # child_process.spawn (HIGH)
    "CMD103": 15,  # child_process.execSync (HIGH)
    
    "FIL101": 1,   # fs.readFile (LOW)
    "FIL102": 1,   # fs.writeFile (LOW)
    "FIL103": 1,   # fs.open (LOW)
    
    "NET101": 1,   # fetch (LOW)
    "NET102": 5,   # axios (MEDIUM)
    "NET103": 1,   # http.request (LOW)
    "NET104": 1,   # https.request (LOW)
    
    "SEC102": 1,   # process.env (LOW)

    # Dependency Analyzer (DEP)
    "DEP001": 15,  # typosquatting (HIGH)
    "DEP002": 1,   # duplicate packages (LOW)
    "DEP003": 5,   # excessive permission packages (MEDIUM)

    # Dockerfile Analyzer (DKR)
    "DKR001": 15,  # USER root (HIGH)
    "DKR002": 5,   # No USER instruction (MEDIUM)
    "DKR003": 25,  # Remote script run (curl | bash) (CRITICAL)
    "DKR004": 15,  # ADD remote URL (HIGH)
    "DKR005": 15,  # chmod 777 (HIGH)
    "DKR006": 15,  # privileged flag (HIGH)

    # GitHub Actions Analyzer (GHA)
    "GHA001": 25,  # Remote script download/run (CRITICAL)
    "GHA002": 5,   # Action not pinned to commit SHA (MEDIUM)
    "GHA003": 25,  # Hardcoded token or secret (CRITICAL)

    # Secret Analyzer (SEC)
    "SEC101": 25,  # Hardcoded credentials (CRITICAL)

    # Network Destination Analyzer (NET)
    "NET201": 1,   # External destination audit (LOW)
}

def calculate_score(findings: List[Finding], repo_path: Path = None) -> int:
    """
    Calculate the total risk score by summing the weights of all HIGH and CRITICAL findings.
    LOW and MEDIUM findings are capabilities and excluded from risk score.
    """
    security_findings = [f for f in findings if f.severity.upper() in {"HIGH", "CRITICAL"}]
    
    # 1. Determine project context
    project_context = ProjectContext.GENERIC
    if repo_path:
        try:
            project_context = ContextAnalyzer().analyze_context(repo_path)
        except Exception:
            pass

    # Filesystem rule IDs to exempt if scanned repository is a security scanner or CLI tool
    filesystem_exempt_ids = {
        "FIL001", "FIL002", "FIL003", "FIL004",  # Python
        "FIL101", "FIL102", "FIL103"              # JS/TS
    }

    counts = {}
    for f in security_findings:
        if project_context in {ProjectContext.SECURITY_SCANNER, ProjectContext.CLI_TOOL} and f.id in filesystem_exempt_ids:
            continue
        counts[f.id] = counts.get(f.id, 0) + 1
        
    total_score = 0
    for fid, count in counts.items():
        base_score = ID_SCORES.get(fid, 0)
        if count >= 2:
            total_score += base_score + max(1, int(0.2 * base_score))
        elif count == 1:
            total_score += base_score
            
    return total_score

def evaluate_risk(findings: List[Finding], repo_path: Path = None) -> tuple[int, RiskLevel]:
    """
    Calculate risk score and evaluate the overall RiskLevel.
    """
    score = calculate_score(findings, repo_path)
    risk_level = get_risk_level(score)
    return score, risk_level
