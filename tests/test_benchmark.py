import pytest
from pathlib import Path
from typer.testing import CliRunner
from skillguard.app import app
from skillguard.models.report import RepositoryReport, PermissionLevel, PermissionFootprint
from skillguard.models.risk import RiskLevel
from skillguard.core.trust_score import TrustScoreReport
from skillguard.reports.benchmark_report import write_benchmark_report

runner = CliRunner()

def test_benchmark_html_report_generation(tmp_path: Path):
    # Setup mock reports
    repo1 = RepositoryReport(
        name="test-repo-1",
        path="https://github.com/user/test-repo-1",
        score=0,
        risk=RiskLevel.LOW,
        trust_score=TrustScoreReport(
            overall_score=95,
            code_safety=95,
            supply_chain_safety=100,
            secrets_hygiene=100,
            network_risk=100,
            container_security=100,
            reasons=["+ Clean code"],
            top_risks=[],
            most_common_behaviors=[]
        ),
        permission_footprint=PermissionFootprint(
            network_access=PermissionLevel.NONE,
            filesystem_access=PermissionLevel.NONE,
            environment_access=PermissionLevel.NONE,
            database_access=PermissionLevel.NONE,
            browser_automation=PermissionLevel.NONE,
            command_execution=PermissionLevel.NONE,
            container_management=PermissionLevel.NONE,
            git_operations=PermissionLevel.NONE
        ),
        findings=[],
        evaluation_report=None,
        project_type="Generic",
        verdict="SAFE"
    )

    repo2 = RepositoryReport(
        name="test-repo-2",
        path="https://github.com/user/test-repo-2",
        score=15,
        risk=RiskLevel.LOW,
        trust_score=TrustScoreReport(
            overall_score=85,
            code_safety=85,
            supply_chain_safety=100,
            secrets_hygiene=100,
            network_risk=100,
            container_security=100,
            reasons=["- Command execution detected"],
            top_risks=[],
            most_common_behaviors=[]
        ),
        permission_footprint=PermissionFootprint(
            network_access=PermissionLevel.NONE,
            filesystem_access=PermissionLevel.NONE,
            environment_access=PermissionLevel.NONE,
            database_access=PermissionLevel.NONE,
            browser_automation=PermissionLevel.NONE,
            command_execution=PermissionLevel.HIGH,
            container_management=PermissionLevel.NONE,
            git_operations=PermissionLevel.NONE
        ),
        findings=[],
        evaluation_report=None,
        project_type="Generic",
        verdict="REVIEW RECOMMENDED"
    )

    output_file = tmp_path / "benchmark.html"
    write_benchmark_report([repo1, repo2], str(output_file))

    assert output_file.exists()
    content = output_file.read_text(encoding="utf-8")
    assert "test-repo-1" in content
    assert "test-repo-2" in content
    assert "95/100" in content
    assert "85/100" in content
    assert "SAFE" in content
    assert "REVIEW RECOMMENDED" in content

def test_benchmark_cli_no_urls_file(tmp_path: Path):
    result = runner.invoke(app, ["benchmark", "non_existent_repos.txt"])
    assert result.exit_code == 1
    assert "File does not exist" in result.stdout

def test_benchmark_cli_empty_urls_file(tmp_path: Path):
    empty_file = tmp_path / "empty.txt"
    empty_file.write_text("", encoding="utf-8")
    result = runner.invoke(app, ["benchmark", str(empty_file)])
    assert result.exit_code == 0
    assert "No repository URLs found" in result.stdout
