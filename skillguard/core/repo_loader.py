import os
from pathlib import Path
from typing import List
import git

EXCLUDED_DIR_NAMES = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    ".idea",
    ".vscode",
    ".pytest_cache",
    "dist",
    "build",
    "tests",  # Don't scan unit tests for vulnerability score
}

def load_repo_files(target_path: str) -> List[Path]:
    """
    Given a target path (file or directory), returns a list of Path objects
    representing all Python files to scan.
    """
    path = Path(target_path).resolve()
    
    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {target_path}")
        
    if path.is_file():
        if path.suffix == ".py":
            return [path]
        return []
        
    # It is a directory, traverse it
    python_files: List[Path] = []
    
    # We can try to check if it's a Git repo
    is_git_repo = False
    try:
        # Check if the directory or any parent is a git repo
        repo = git.Repo(path, search_parent_directories=True)
        is_git_repo = True
    except (git.InvalidGitRepositoryError, git.NoSuchPathError):
        pass

    for root, dirs, files in os.walk(path):
        # In-place modify dirs to skip excluded directories in os.walk
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIR_NAMES and not d.startswith(".")]
        
        for file in files:
            if file.endswith(".py"):
                file_path = Path(root) / file
                python_files.append(file_path)
                
    return python_files
