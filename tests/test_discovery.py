from pathlib import Path
import pytest

from skillguard.core.repository_discovery import discover_language, get_scan_targets

def test_discover_language():
    assert discover_language(Path("test.py")) == "Python"
    assert discover_language(Path("sub/file.js")) == "JavaScript"
    assert discover_language(Path("index.ts")) == "TypeScript"
    assert discover_language(Path("main.go")) == "Go"
    assert discover_language(Path("lib.rs")) == "Rust"
    assert discover_language(Path("README.md")) is None
    assert discover_language(Path("Makefile")) is None

def test_recursive_discovery(tmp_path: Path):
    # Setup mock structure:
    # root/
    #   repo1/
    #     server.py
    #     helper.py
    #   repo2/
    #     index.ts
    #     auth.ts
    #     node_modules/
    #       vuln.js
    #   repo3/
    #     nested/
    #       api.js
    #   repo4/
    #     deeper/
    #       more/
    #         worker.py
    #   venv/
    #     lib.py
    
    repo1 = tmp_path / "repo1"
    repo1.mkdir()
    (repo1 / "server.py").write_text("print('hello')", encoding="utf-8")
    (repo1 / "helper.py").write_text("print('helper')", encoding="utf-8")

    repo2 = tmp_path / "repo2"
    repo2.mkdir()
    (repo2 / "index.ts").write_text("const a = 1;", encoding="utf-8")
    (repo2 / "auth.ts").write_text("const b = 2;", encoding="utf-8")
    
    node_modules = repo2 / "node_modules"
    node_modules.mkdir()
    (node_modules / "vuln.js").write_text("alert(1);", encoding="utf-8")

    repo3 = tmp_path / "repo3"
    repo3.mkdir()
    nested = repo3 / "nested"
    nested.mkdir()
    (nested / "api.js").write_text("console.log('api');", encoding="utf-8")

    repo4 = tmp_path / "repo4"
    repo4.mkdir()
    deeper = repo4 / "deeper" / "more"
    deeper.mkdir(parents=True)
    (deeper / "worker.py").write_text("import os", encoding="utf-8")

    venv = tmp_path / "venv"
    venv.mkdir()
    (venv / "lib.py").write_text("import sys", encoding="utf-8")

    # Run get_scan_targets
    discovered_files, lang_stats, repo_count = get_scan_targets(tmp_path)

    # We expect:
    # - 6 discovered files (server.py, helper.py, index.ts, auth.ts, api.js, worker.py)
    # - node_modules and venv are completely ignored
    # - stats: Python=3 (repo1/server.py, repo1/helper.py, repo4/worker.py), JavaScript=1, TypeScript=2
    # - repositories count: 4 (repo1, repo2, repo3, repo4). venv is ignored, and root has no direct files.
    assert len(discovered_files) == 6
    assert lang_stats["Python"] == 3
    assert lang_stats["JavaScript"] == 1
    assert lang_stats["TypeScript"] == 2
    assert repo_count == 4

def test_git_repo_discovery_priority(tmp_path: Path):
    # Setup mock structure where git repos exist
    # root/
    #   my-git-project/
    #     .git/
    #     main.py
    #   other-git-project/
    #     .git/
    #     index.ts
    
    project1 = tmp_path / "my-git-project"
    project1.mkdir()
    (project1 / ".git").mkdir()
    (project1 / "main.py").write_text("pass", encoding="utf-8")

    project2 = tmp_path / "other-git-project"
    project2.mkdir()
    (project2 / ".git").mkdir()
    (project2 / "index.ts").write_text("pass", encoding="utf-8")

    discovered_files, lang_stats, repo_count = get_scan_targets(tmp_path)

    # repo_count should be exactly 2 (based on git repos detected)
    assert len(discovered_files) == 2
    assert repo_count == 2
