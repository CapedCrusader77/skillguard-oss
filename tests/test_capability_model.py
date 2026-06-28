import json
from pathlib import Path
from skillguard.models.finding import Finding
from skillguard.models.report import Report, PermissionLevel, PermissionFootprint
from skillguard.analysis.project_profiler import ProjectProfiler, ProjectType, Capability
from skillguard.core.trust_score import calculate_trust_score
from skillguard.core.scoring import calculate_score

def test_project_profiler_detection(tmp_path: Path):
    # Setup mock frontend app structure
    fe_dir = tmp_path / "my_frontend"
    fe_dir.mkdir()
    
    # 1. Manifest / package.json with react dependency
    pkg_json = fe_dir / "package.json"
    pkg_json.write_text(json.dumps({
        "name": "my-react-app",
        "dependencies": {
            "react": "^18.2.0"
        }
    }), encoding="utf-8")
    
    profiler = ProjectProfiler()
    project_type = profiler.profile_project(fe_dir)
    assert project_type == ProjectType.FRONTEND

def test_project_profiler_mcp_detection(tmp_path: Path):
    mcp_dir = tmp_path / "mcp_utility"
    mcp_dir.mkdir()
    
    readme = mcp_dir / "README.md"
    readme.write_text("# Weather MCP Server\nThis is a Model Context Protocol tool.", encoding="utf-8")
    
    profiler = ProjectProfiler()
    project_type = profiler.profile_project(mcp_dir)
    assert project_type == ProjectType.MCP_SERVER

def test_unexpected_capabilities():
    profiler = ProjectProfiler()
    
    # Frontend App with command execution (unexpected)
    active = {Capability.NETWORK, Capability.ENVIRONMENT, Capability.COMMAND}
    unexpected = profiler.get_unexpected_capabilities(ProjectType.FRONTEND, active)
    assert Capability.COMMAND in unexpected
    assert Capability.NETWORK not in unexpected

def test_findings_separation():
    # Simulate a set of findings containing LOW, MEDIUM, and HIGH severities
    findings = [
        Finding(id="FIL001", severity="LOW", category="FILE_SYSTEM", file="a.py", line=1, message="open"),
        Finding(id="NET001", severity="MEDIUM", category="NETWORK", file="a.py", line=2, message="requests.post"),
        Finding(id="CMD001", severity="HIGH", category="COMMAND_EXECUTION", file="a.py", line=3, message="Popen")
    ]
    
    # Verify calculate_score only counts HIGH/CRITICAL findings
    score = calculate_score(findings)
    # CMD001 is 15. The rest are LOW/MEDIUM and are capabilities (ignored).
    assert score == 15

def test_executive_summary_verdicts(tmp_path: Path):
    # If no findings: SAFE
    findings_safe = []
    trust_report = calculate_trust_score(findings_safe, tmp_path)
    assert trust_report.overall_score == 100
    
    # If CRITICAL finding: DANGEROUS
    findings_danger = [
        Finding(id="SEC101", severity="CRITICAL", category="SECRET_ACCESS", file=".env", line=1, message="API Key found")
    ]
    trust_report_danger = calculate_trust_score(findings_danger, tmp_path)
    assert trust_report_danger.overall_score < 100
