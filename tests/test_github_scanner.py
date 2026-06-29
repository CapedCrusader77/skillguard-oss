import subprocess
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from typer.testing import CliRunner

from skillguard.app import app
from skillguard.core.github_scanner import (
    is_github_url,
    get_repository_name,
    clone_repository,
    cleanup_repository,
    GitHubScannerError,
    GitNotInstalledError,
    InvalidGitHubURLError,
    CloneFailureError
)

runner = CliRunner()

def test_is_github_url():
    # Valid URLs
    assert is_github_url("https://github.com/user/repo") is True
    assert is_github_url("https://github.com/user/repo.git") is True
    assert is_github_url("http://github.com/user/repo") is True
    assert is_github_url("https://www.github.com/user/repo") is True
    assert is_github_url("git@github.com:user/repo.git") is True
    assert is_github_url("https://github.com/user/repo/") is True

    # Invalid URLs
    assert is_github_url("https://gitlab.com/user/repo") is False
    assert is_github_url("https://github.com/user") is False
    assert is_github_url("not_a_url") is False
    assert is_github_url("https://github.com") is False

def test_get_repository_name():
    assert get_repository_name("https://github.com/user/repo") == "repo"
    assert get_repository_name("https://github.com/user/repo.git") == "repo"
    assert get_repository_name("git@github.com:user/repo.git") == "repo"
    
    with pytest.raises(InvalidGitHubURLError):
        get_repository_name("https://gitlab.com/user/repo")

@patch("shutil.which")
@patch("subprocess.run")
def test_clone_repository_success(mock_run, mock_which):
    mock_which.return_value = "/usr/bin/git"
    mock_run.return_value = MagicMock(returncode=0)
    
    temp_dir = "/tmp/fake_dir"
    res = clone_repository("https://github.com/user/repo", temp_dir)
    
    assert res == Path(temp_dir)
    mock_run.assert_called_once_with(
        ["git", "clone", "--depth", "1", "https://github.com/user/repo", temp_dir],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True
    )

@patch("shutil.which")
def test_clone_repository_git_missing(mock_which):
    mock_which.return_value = None
    
    with pytest.raises(GitNotInstalledError):
        clone_repository("https://github.com/user/repo", "/tmp/fake_dir")

@patch("shutil.which")
@patch("subprocess.run")
def test_clone_repository_failures(mock_run, mock_which):
    mock_which.return_value = "/usr/bin/git"
    
    # Mock network failure
    mock_run.side_effect = subprocess.CalledProcessError(
        returncode=128,
        cmd="git clone ...",
        stderr="fatal: Could not resolve host: github.com"
    )
    with pytest.raises(CloneFailureError) as exc_info:
        clone_repository("https://github.com/user/repo", "/tmp/fake_dir")
    assert "Network failure" in str(exc_info.value)
    
    # Mock private repo / access denied
    mock_run.side_effect = subprocess.CalledProcessError(
        returncode=128,
        cmd="git clone ...",
        stderr="fatal: Repository not found"
    )
    with pytest.raises(CloneFailureError) as exc_info:
        clone_repository("https://github.com/user/repo", "/tmp/fake_dir")
    assert "Failed to access repository" in str(exc_info.value)
    
    # Mock general error
    mock_run.side_effect = subprocess.CalledProcessError(
        returncode=1,
        cmd="git clone ...",
        stderr="fatal: some other git error"
    )
    with pytest.raises(CloneFailureError) as exc_info:
        clone_repository("https://github.com/user/repo", "/tmp/fake_dir")
    assert "Git clone failed: fatal: some other git error" in str(exc_info.value)

@patch("shutil.rmtree")
def test_cleanup_repository(mock_rmtree, tmp_path):
    cleanup_repository(str(tmp_path))
    mock_rmtree.assert_called_once()

@patch("skillguard.app.clone_repository")
@patch("skillguard.app.get_scan_targets")
@patch("skillguard.core.repository_discovery.discover_files")
@patch("skillguard.app.group_files_by_repository")
def test_cli_github_scan(mock_group_files, mock_discover_files, mock_get_scan_targets, mock_clone_repository, tmp_path):
    # Prepare mock inputs
    repo_url = "https://github.com/user/my-cool-repo"
    
    # Setup mock scanning targets
    mock_file = Path("/tmp/fake_temp_dir/main.py")
    mock_get_scan_targets.return_value = ([mock_file], {"Python": 1}, 1)
    
    # Setup discover_files & group_files
    mock_discover_files.return_value = ([mock_file], set(), set())
    mock_group_files.return_value = {Path("/tmp/fake_temp_dir"): [mock_file]}
    
    # We also mock write_report_json to not touch real filesystem
    with patch("skillguard.app.write_report_json") as mock_write_json:
        mock_write_json.return_value = Path("report.json")
        
        result = runner.invoke(app, ["scan", repo_url])
        
        assert result.exit_code == 0
        assert "Repository Source:" in result.stdout
        assert "GitHub" in result.stdout
        assert "Repository URL:" in result.stdout
        assert repo_url in result.stdout
        assert "Repository Name:" in result.stdout
        assert "my-cool-repo" in result.stdout
        
        mock_clone_repository.assert_called_once()
