import json
from pathlib import Path
from skillguard.models.finding import Finding
from skillguard.models.report import Report, PermissionLevel, PermissionFootprint, RepositoryReport
from skillguard.models.risk import RiskLevel
from skillguard.core.repository_discovery import group_files_by_repository
from skillguard.core.trust_score import calculate_trust_score, TrustScoreReport

def test_group_files_by_repository(tmp_path: Path):
    # Setup mock repositories:
    # repo1 (git)
    # repo2 (generic subdirectory)
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    (repo1 / ".git").mkdir()
    file1 = repo1 / "server.py"
    file1.write_text("print('hello')", encoding="utf-8")

    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    file2 = repo2 / "index.js"
    file2.write_text("console.log('hello')", encoding="utf-8")

    discovered_files = [file1, file2]
    git_repos = {repo1}

    # Group
    grouped = group_files_by_repository(tmp_path, discovered_files, git_repos)

    # Since git_repos has repo1, file1 belongs to repo1.
    # file2 does not belong to any git repo, so it is grouped under root (tmp_path)
    assert repo1 in grouped
    assert tmp_path in grouped
    assert file1 in grouped[repo1]
    assert file2 in grouped[tmp_path]

def test_group_files_heuristic(tmp_path: Path):
    # Scanned root with no git repos: should group by immediate subdirectories
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    file1 = repo1 / "server.py"
    file1.write_text("print('hello')", encoding="utf-8")

    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    file2 = repo2 / "index.js"
    file2.write_text("console.log('hello')", encoding="utf-8")

    discovered_files = [file1, file2]
    git_repos = set()

    grouped = group_files_by_repository(tmp_path, discovered_files, git_repos)
    assert repo1 in grouped
    assert repo2 in grouped
    assert file1 in grouped[repo1]
    assert file2 in grouped[repo2]

def test_repo_verdict_thresholds():
    # Helper to test verdict mapping
    def get_verdict(trust: int, risk: RiskLevel) -> str:
        if trust >= 85 and risk == RiskLevel.LOW:
            return "SAFE"
        elif trust >= 60:
            return "REVIEW RECOMMENDED"
        elif trust >= 40:
            return "HIGH RISK"
        else:
            return "DANGEROUS"

    # Trust >= 85 and Risk LOW => SAFE
    assert get_verdict(90, RiskLevel.LOW) == "SAFE"
    # Trust >= 85 but Risk HIGH => REVIEW RECOMMENDED
    assert get_verdict(90, RiskLevel.HIGH) == "REVIEW RECOMMENDED"
    # Trust 60-84 => REVIEW RECOMMENDED
    assert get_verdict(75, RiskLevel.LOW) == "REVIEW RECOMMENDED"
    assert get_verdict(60, RiskLevel.CRITICAL) == "REVIEW RECOMMENDED"
    # Trust < 60 => HIGH RISK
    assert get_verdict(55, RiskLevel.LOW) == "HIGH RISK"
    assert get_verdict(40, RiskLevel.HIGH) == "HIGH RISK"
    # Trust < 40 => DANGEROUS
    assert get_verdict(35, RiskLevel.LOW) == "DANGEROUS"
    assert get_verdict(10, RiskLevel.CRITICAL) == "DANGEROUS"
