import json
from pathlib import Path
from typer.testing import CliRunner
import pytest

from skillguard.analysis.models import ClaimedCategory, BehaviorProfile, ProjectClaims
from skillguard.analysis.claim_extractor import RuleBasedClaimExtractor
from skillguard.analysis.behavior_analyzer import BehaviorAnalyzer
from skillguard.analysis.trust_evaluator import TrustEvaluator
from skillguard.models.finding import Finding
from skillguard.app import app

runner = CliRunner()

def test_claim_extractor(tmp_path: Path):
    # Setup mock files
    # 1. package.json description
    pkg_file = tmp_path / "package.json"
    pkg_file.write_text(json.dumps({"description": "An interactive Weather and climate monitoring tool"}), encoding="utf-8")
    
    # 2. pyproject.toml
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('description = "Fallback pyproject info"', encoding="utf-8")

    # 3. README.md
    readme = tmp_path / "README.md"
    readme.write_text("# Meteorology Tool\nThis weather forecast script calculates climate information.\n", encoding="utf-8")

    extractor = RuleBasedClaimExtractor()
    claims = extractor.extract_claims(tmp_path)

    # Expected: Claimed purpose is from package.json since it is read first.
    # Extracted category is WEATHER
    assert "Weather" in claims.claimed_purpose
    assert ClaimedCategory.WEATHER in claims.categories

def test_behavior_analyzer(tmp_path: Path):
    # Setup mock code file with imports that trigger behaviors
    code_file = tmp_path / "app.py"
    code_content = """
import sqlite3
import smtplib
from playwright.async_api import async_playwright

def run():
    print("Database, email, and browser tests")
    """
    code_file.write_text(code_content, encoding="utf-8")

    # Mock some findings to trigger others (e.g., filesystem, network)
    findings = [
        Finding(id="FIL001", severity="LOW", category="FILE_SYSTEM", file="app.py", line=10, message="open"),
        Finding(id="NET001", severity="MEDIUM", category="NETWORK", file="app.py", line=12, message="requests.post")
    ]

    analyzer = BehaviorAnalyzer()
    profile = analyzer.analyze_behavior(tmp_path, findings)

    assert profile.database_access is True
    assert profile.email_access is True
    assert profile.browser_automation is True
    assert profile.filesystem_access is True
    assert profile.network_access is True
    assert profile.credential_access is False

def test_trust_evaluator():
    # Setup a weather claims profile
    claims = ProjectClaims(
        claimed_purpose="Simple Weather MCP Server",
        categories=[ClaimedCategory.WEATHER]
    )

    # Behavior profile contains filesystem, network, and credentials access
    # Since Weather category only expects network_access, filesystem and credential access are mismatches
    behavior = BehaviorProfile(
        filesystem_access=True,
        network_access=True,
        credential_access=True,
        database_access=False,
        email_access=False,
        browser_automation=False
    )

    evaluator = TrustEvaluator()
    report = evaluator.evaluate(claims, behavior)

    # Deductions: filesystem_access (30) + credential_access (30) = 60
    # Score: 95 - 60 = 35
    assert report.trust_score == 35
    assert "Undeclared filesystem access" in report.mismatches
    assert "Undeclared credential access" in report.mismatches
    assert len(report.mismatches) == 2
    assert report.verdict == "Behavior exceeds declared functionality"

def test_cli_scan_trust_flag(tmp_path: Path):
    # Setup dummy weather repo to scan
    readme = tmp_path / "README.md"
    readme.write_text("# Weather Service\nReads forecasts from the meteorology network.\n", encoding="utf-8")
    
    script = tmp_path / "server.py"
    # Triggers: filesystem (open), network (requests.post), credential (os.getenv)
    script_content = """
import os
import requests

key = os.getenv("API_KEY")
with open("cache.json", "w") as f:
    f.write(requests.post("http://weather.com/api", data=key).text)
    """
    script.write_text(script_content, encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--trust"])

    # High mismatches (score 35) should cause exit code 1
    assert result.exit_code == 1
    assert "Claimed Purpose:" in result.stdout
    assert "Reads forecasts from the meteorology network" in result.stdout
    assert "Observed Behavior:" in result.stdout
    assert "Filesystem Access" in result.stdout
    assert "Network Access" in result.stdout
    assert "Credential Access" in result.stdout
    assert "Warnings:" in result.stdout
    assert "Undeclared filesystem access" in result.stdout
    assert "Undeclared credential access" in result.stdout
    assert "Verdict: Behavior exceeds declared functionality" in result.stdout
