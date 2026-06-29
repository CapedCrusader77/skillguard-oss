import os
import re
import shutil
import subprocess
from pathlib import Path

# Matches https://github.com/owner/repo or https://github.com/owner/repo.git or git@github.com:owner/repo.git
# and ignores trailing slashes.
GITHUB_URL_REGEX = re.compile(
    r'^(?:https?://(?:www\.)?github\.com/([^/]+)/([^/.]+?)(?:\.git)?/?'
    r'|git@github\.com:([^/]+)/([^/.]+?)(?:\.git)?/?)$',
    re.IGNORECASE
)

class GitHubScannerError(Exception):
    """Base exception for GitHub scanner errors."""
    pass

class GitNotInstalledError(GitHubScannerError):
    """Raised when Git is not installed."""
    pass

class InvalidGitHubURLError(GitHubScannerError):
    """Raised when the provided URL is not a valid GitHub URL."""
    pass

class CloneFailureError(GitHubScannerError):
    """Raised when cloning the repository fails (network, private repo, etc.)."""
    pass

def is_github_url(url: str) -> bool:
    """
    Detect if the given URL is a valid GitHub repository URL.
    """
    return bool(GITHUB_URL_REGEX.match(url))

def get_repository_name(url: str) -> str:
    """
    Extract the repository name from a GitHub URL.
    """
    match = GITHUB_URL_REGEX.match(url)
    if not match:
        raise InvalidGitHubURLError(f"Invalid GitHub repository URL: {url}")
    # Group 2 is for https format, Group 4 is for ssh format
    name = match.group(2) or match.group(4)
    return name

def clone_repository(url: str, temp_dir: str) -> Path:
    """
    Clone a GitHub repository to a temporary directory using a shallow clone.
    """
    if not is_github_url(url):
        raise InvalidGitHubURLError(f"Invalid GitHub repository URL: {url}")
        
    if not shutil.which("git"):
        raise GitNotInstalledError("Git CLI is not installed or not found in system PATH.")
        
    try:
        # Run shallow clone: git clone --depth 1 <url> <temp_dir>
        subprocess.run(
            ["git", "clone", "--depth", "1", url, temp_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return Path(temp_dir)
    except subprocess.CalledProcessError as e:
        stderr = e.stderr or ""
        # Inspect stderr for user-friendly errors
        if "Could not resolve host" in stderr:
            raise CloneFailureError("Network failure: Could not resolve github.com. Please check your internet connection.")
        elif "Repository not found" in stderr or "Permission denied" in stderr or "fatal: Authentication failed" in stderr or "terminal prompts disabled" in stderr:
            raise CloneFailureError("Failed to access repository. It may be private, require authentication, or does not exist.")
        else:
            raise CloneFailureError(f"Git clone failed: {stderr.strip()}")

def cleanup_repository(temp_dir: str) -> None:
    """
    Safely delete the temporary repository directory, handling read-only files.
    """
    path = Path(temp_dir)
    if not path.exists():
        return
        
    def _onerror(func, filepath, exc_info):
        import stat
        try:
            os.chmod(filepath, stat.S_IWRITE)
            func(filepath)
        except Exception:
            pass
            
    shutil.rmtree(temp_dir, onerror=_onerror)
