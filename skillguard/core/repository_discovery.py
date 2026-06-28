import os
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional

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
    ".dart_tool",        # Flutter generated tool directory
    ".flutter-plugins",
}

SUPPORTED_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".dart": "Dart",
}

# Extensible extensions mapping for future languages
EXTENSIBLE_EXTENSIONS = {
    ".go": "Go",
    ".rs": "Rust",
}

# Flutter standard structural subdirectories.
# These should never be treated as independent repository roots —
# they are internal parts of a single Flutter project.
FLUTTER_STRUCTURAL_DIRS = {
    "ios",
    "android",
    "lib",
    "test",
    "web",
    "macos",
    "windows",
    "linux",
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

def detect_flutter_roots(root_path: Path) -> Set[Path]:
    """
    Recursively scan root_path for directories containing pubspec.yaml.
    Each such directory is a Flutter/Dart project root and should be
    treated as a single repository regardless of its internal structure.
    """
    flutter_roots: Set[Path] = set()
    if root_path.is_file():
        return flutter_roots

    resolved = root_path.resolve()
    for dirpath, dirnames, filenames in os.walk(resolved):
        current = Path(dirpath)
        # Prune ignored dirs from descent
        dirnames[:] = [
            d for d in dirnames
            if d not in IGNORE_DIRS and not d.startswith(".")
        ]
        if "pubspec.yaml" in filenames:
            flutter_roots.add(current)

    return flutter_roots

def discover_files(root_path: Path) -> Tuple[List[Path], Set[Path], Set[Path]]:
    """
    Recursively discover all supported files in every nested directory.
    Returns:
        - A list of discovered source file Path objects.
        - A set of paths identified as Git repositories (containing a .git directory).
        - A set of paths identified as Flutter project roots (containing pubspec.yaml).
    """
    discovered_files: List[Path] = []
    git_repos: Set[Path] = set()
    flutter_roots: Set[Path] = set()

    # If the path is a single file, handle it immediately
    if root_path.is_file():
        if discover_language(root_path) in SUPPORTED_EXTENSIONS.values():
            discovered_files.append(root_path)
        return discovered_files, git_repos, flutter_roots

    # Resolve target directory
    resolved_root = root_path.resolve()

    for root, dirs, files in os.walk(resolved_root):
        current_dir = Path(root)

        # Check if this directory is a Git repository
        if ".git" in dirs:
            git_repos.add(current_dir)

        # Check if this directory is a Flutter project root
        if "pubspec.yaml" in files:
            flutter_roots.add(current_dir)

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

    # If the root itself is a Flutter project
    if (resolved_root / "pubspec.yaml").exists():
        flutter_roots.add(resolved_root)

    return discovered_files, git_repos, flutter_roots

def get_scan_targets(root_path: Path) -> Tuple[List[Path], Dict[str, int], int]:
    """
    Discovers all supported files under root_path, aggregates language counts,
    and calculates the number of distinct repositories found.
    """
    path = Path(root_path).resolve()
    if not path.exists():
        raise FileNotFoundError(f"Path does not exist: {root_path}")

    # Step 1: Discover files, git repos, and Flutter roots
    discovered_files, git_repos, flutter_roots = discover_files(path)

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

    # Merge all project roots (git + flutter) — each is a distinct repo
    all_project_roots = git_repos | flutter_roots

    if all_project_roots:
        # Remove roots that are children of other roots (nested monorepos)
        # to avoid double-counting. Keep the most specific (deepest) root per file.
        repo_count = len(all_project_roots)
    else:
        # Heuristic: Count immediate subdirectories that contain discovered files,
        # excluding Flutter structural dirs, plus root if it has direct files.
        active_subdirs: Set[Path] = set()
        has_root_files = False

        for f in discovered_files:
            try:
                relative = f.relative_to(path)
                parts = relative.parts
                if len(parts) > 1:
                    first_dir = parts[0]
                    # Skip Flutter structural dirs — they belong to the parent
                    if first_dir not in FLUTTER_STRUCTURAL_DIRS:
                        active_subdirs.add(path / first_dir)
                    else:
                        has_root_files = True  # treat as belonging to root
                else:
                    has_root_files = True
            except ValueError:
                has_root_files = True

        repo_count = len(active_subdirs)
        if has_root_files:
            repo_count += 1

        # Ensure that if we have files but 0 calculated repositories, fall back to 1
        if repo_count == 0 and discovered_files:
            repo_count = 1

    return discovered_files, lang_stats, repo_count

def group_files_by_repository(
    root_path: Path,
    discovered_files: List[Path],
    git_repos: Set[Path],
    flutter_roots: Optional[Set[Path]] = None,
) -> Dict[Path, List[Path]]:
    """
    Groups discovered files under their respective repository root directories.

    Priority order:
      1. Git repositories (closest ancestor .git)
      2. Flutter project roots (closest ancestor pubspec.yaml)
      3. Heuristic: immediate subdirectories of root_path, skipping
         Flutter structural dirs (ios/android/lib/test/…).
    """
    if root_path.is_file():
        return {root_path.parent: [root_path]}

    repos: Dict[Path, List[Path]] = {}

    # Merge git repos and flutter roots into a single set of project roots
    all_roots: Set[Path] = set(git_repos)
    if flutter_roots:
        all_roots |= flutter_roots

    if all_roots:
        # Sort deepest first so the most specific ancestor wins
        sorted_roots = sorted(all_roots, key=lambda p: len(p.parts), reverse=True)
        for f in discovered_files:
            matched = False
            for repo in sorted_roots:
                if repo == f or repo in f.parents:
                    repos.setdefault(repo, []).append(f)
                    matched = True
                    break
            if not matched:
                repos.setdefault(root_path, []).append(f)
    else:
        # Heuristic: immediate subdirectories, but collapse Flutter structural
        # dirs back to their parent (treating the parent as the project root).
        for f in discovered_files:
            try:
                relative = f.relative_to(root_path)
                parts = relative.parts
                if len(parts) > 1:
                    first_dir = parts[0]
                    if first_dir in FLUTTER_STRUCTURAL_DIRS:
                        # Belongs to the parent directory (the Flutter project root)
                        repo_path = root_path
                    else:
                        repo_path = root_path / first_dir
                else:
                    repo_path = root_path
                repos.setdefault(repo_path, []).append(f)
            except ValueError:
                repos.setdefault(root_path, []).append(f)

    return repos


