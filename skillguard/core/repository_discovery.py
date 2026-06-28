import os
from pathlib import Path
from typing import List, Dict, Set, Tuple

IGNORE_DIRS = {
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "dist",
    "build",
    ".next",
    "coverage",
    "target",
    "out",
    "bin",
}

SUPPORTED_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
}

# Extensible extensions mapping for future languages
EXTENSIBLE_EXTENSIONS = {
    ".go": "Go",
    ".rs": "Rust",
}

def discover_language(file_path: Path) -> str | None:
    """
    Returns the programming language of a file based on its extension,
    supporting both current and future extensible formats.
    """
    ext = file_path.suffix.lower()
    if ext in SUPPORTED_EXTENSIONS:
        return SUPPORTED_EXTENSIONS[ext]
    if ext in EXTENSIBLE_EXTENSIONS:
        return EXTENSIBLE_EXTENSIONS[ext]
    return None

def discover_files(root_path: Path) -> Tuple[List[Path], Set[Path]]:
    """
    Recursively discover all supported files in every nested directory.
    Returns:
        - A list of discovered source file Path objects.
        - A set of paths identified as Git repositories (containing a .git directory).
    """
    discovered_files: List[Path] = []
    git_repos: Set[Path] = set()

    # If the path is a single file, handle it immediately
    if root_path.is_file():
        if discover_language(root_path) in SUPPORTED_EXTENSIONS.values():
            discovered_files.append(root_path)
        return discovered_files, git_repos

    # Resolve target directory
    resolved_root = root_path.resolve()

    for root, dirs, files in os.walk(resolved_root):
        current_dir = Path(root)
        
        # Check if this directory is a Git repository
        if ".git" in dirs:
            git_repos.add(current_dir)
            
        # In-place modify dirs to skip ignored directories and hidden folders
        dirs[:] = [
            d for d in dirs
            if d not in IGNORE_DIRS and not d.startswith(".")
        ]

        for file in files:
            file_path = current_dir / file
            lang = discover_language(file_path)
            if lang in SUPPORTED_EXTENSIONS.values():
                discovered_files.append(file_path)

    # If the root itself is a git repository (contains .git directly)
    if (resolved_root / ".git").exists():
        git_repos.add(resolved_root)

    return discovered_files, git_repos

def get_scan_targets(root_path: Path) -> Tuple[List[Path], Dict[str, int], int]:
    """
    Discovers all supported files under root_path, aggregates language counts,
    and calculates the number of distinct repositories found.
    """
    path = Path(root_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {root_path}")

    # Step 1: Discover files and git repos
    discovered_files, git_repos = discover_files(path)

    # Step 2: Aggregate language stats
    lang_stats: Dict[str, int] = {lang: 0 for lang in SUPPORTED_EXTENSIONS.values()}
    for f in discovered_files:
        lang = discover_language(f)
        if lang:
            lang_stats[lang] = lang_stats.get(lang, 0) + 1

    # Step 3: Determine repository count
    # If the target is a file, it's 1 repository
    if path.is_file():
        repo_count = 1 if discovered_files else 0
        return discovered_files, lang_stats, repo_count

    # If git repositories were explicitly discovered during walk
    if git_repos:
        repo_count = len(git_repos)
    else:
        # Heuristic: Count immediate subdirectories that contain discovered files,
        # plus the root directory if it contains files directly.
        active_subdirs = set()
        has_root_files = False

        for f in discovered_files:
            try:
                # Find the direct child of root_path that is a parent of this file
                relative = f.relative_to(path)
                parts = relative.parts
                if len(parts) > 1:
                    active_subdirs.add(path / parts[0])
                else:
                    has_root_files = True
            except ValueError:
                # Fallback if path calculations mismatch
                has_root_files = True

        repo_count = len(active_subdirs)
        if has_root_files:
            repo_count += 1
            
        # Ensure that if we have files but 0 calculated repositories, we fall back to 1
        if repo_count == 0 and discovered_files:
            repo_count = 1

    return discovered_files, lang_stats, repo_count

def group_files_by_repository(root_path: Path, discovered_files: List[Path], git_repos: Set[Path]) -> Dict[Path, List[Path]]:
    """
    Groups discovered files under their respective repository root directories.
    If git repositories exist, files are grouped under the closest containing git repo root.
    Otherwise, they are grouped under root_path's immediate subdirectories (or root_path itself if directly in root).
    """
    if root_path.is_file():
        return {root_path.parent: [root_path]}

    repos: Dict[Path, List[Path]] = {}
    
    # If git repos exist, group by matching repo root prefix
    if git_repos:
        sorted_repos = sorted(list(git_repos), key=lambda p: len(p.parts), reverse=True)
        for f in discovered_files:
            matched = False
            for repo in sorted_repos:
                if repo == f or repo in f.parents:
                    repos.setdefault(repo, []).append(f)
                    matched = True
                    break
            if not matched:
                repos.setdefault(root_path, []).append(f)
    else:
        # Heuristic: immediate subdirectories are repositories. Root files belong to root_path.
        for f in discovered_files:
            try:
                relative = f.relative_to(root_path)
                parts = relative.parts
                if len(parts) > 1:
                    repo_path = root_path / parts[0]
                else:
                    repo_path = root_path
                repos.setdefault(repo_path, []).append(f)
            except ValueError:
                repos.setdefault(root_path, []).append(f)
                
    return repos
