import ast
from pathlib import Path
import pytest

from skillguard.models.finding import Finding
from skillguard.scanners.command_detector import CommandDetector
from skillguard.scanners.file_detector import FileDetector
from skillguard.scanners.network_detector import NetworkDetector
from skillguard.scanners.secret_detector import SecretDetector
from skillguard.scanners.javascript_scanner import JavaScriptScanner
from skillguard.scanners.typescript_scanner import TypeScriptScanner

# Helper to run a detector on source code
def run_detector(detector_cls, source_code: str) -> list[Finding]:
    tree = ast.parse(source_code)
    # Use dummy paths for testing
    file_path = Path("test_file.py")
    project_root = Path(".")
    
    detector = detector_cls(file_path, project_root)
    detector.visit(tree)
    return detector.findings

def test_command_detector():
    code = """
import subprocess
import os
subprocess.Popen(["ls"])
subprocess.run("echo hello", shell=True)
os.system("whoami")
    """
    findings = run_detector(CommandDetector, code)
    
    # We expect:
    # 1. subprocess.Popen (CMD001)
    # 2. subprocess.run (CMD002)
    # 3. shell=True (CMD005)
    # 4. os.system (CMD004)
    assert len(findings) == 4
    
    ids = {f.id for f in findings}
    assert "CMD001" in ids
    assert "CMD002" in ids
    assert "CMD005" in ids
    assert "CMD004" in ids
    
    # Check that subprocess.run and shell=True are on the same line (line 5)
    run_finding = [f for f in findings if f.id == "CMD002"][0]
    shell_finding = [f for f in findings if f.id == "CMD005"][0]
    assert run_finding.line == 5
    assert shell_finding.line == 5

def test_file_detector():
    code = """
from pathlib import Path
import os
import glob

with open("test.txt") as f:
    pass
p = Path("abc")
os.walk(".")
glob.glob("*.py")
    """
    findings = run_detector(FileDetector, code)
    
    assert len(findings) == 4
    ids = {f.id for f in findings}
    assert "FIL001" in ids  # open()
    assert "FIL002" in ids  # pathlib.Path
    assert "FIL003" in ids  # os.walk
    assert "FIL004" in ids  # glob.glob

def test_network_detector():
    code = """
import requests
import httpx
import urllib.request
import socket

requests.get("https://google.com")
requests.post("https://api.github.com", json={})
httpx.post("https://httpbin.org")
urllib.request.urlopen("https://python.org")
s = socket.socket()
    """
    findings = run_detector(NetworkDetector, code)
    
    assert len(findings) == 5
    ids = {f.id for f in findings}
    assert "NET002" in ids  # requests.get
    assert "NET001" in ids  # requests.post
    assert "NET005" in ids  # httpx
    assert "NET006" in ids  # urllib
    assert "NET007" in ids  # socket

def test_secret_detector():
    code = """
import os
from os import environ

key1 = os.getenv("API_KEY")
key2 = os.environ.get("API_KEY")
key3 = os.environ["SECRET"]
key4 = environ["OTHER_SECRET"]
    """
    findings = run_detector(SecretDetector, code)
    
    # We expect:
    # 1. os.getenv on line 5
    # 2. os.environ on line 6
    # 3. os.environ on line 7
    # 4. os.environ on line 8 (due to from os import environ alias)
    assert len(findings) == 4
    
    getenv_findings = [f for f in findings if f.id == "SEC001"]
    environ_findings = [f for f in findings if f.id == "SEC002"]
    
    assert len(getenv_findings) == 1
    assert len(environ_findings) == 3

def test_javascript_scanner(tmp_path: Path):
    js_code = """
// Single line comment referencing process.env or child_process.exec
/* Block comment referencing axios or spawn */
const exec = require('child_process').exec;
exec("rm -rf /");
fs.readFile("test.txt", (err, data) => {});
fetch("https://google.com");
const key = process.env.API_KEY;
    """
    file_path = tmp_path / "test.js"
    file_path.write_text(js_code, encoding="utf-8")
    
    scanner = JavaScriptScanner(file_path, tmp_path)
    findings = scanner.scan()
    
    # We expect:
    # 1. child_process.exec (CMD101)
    # 2. fs.readFile (FIL101)
    # 3. fetch (NET101)
    # 4. process.env (SEC102)
    assert len(findings) == 4
    ids = {f.id for f in findings}
    assert "CMD101" in ids
    assert "FIL101" in ids
    assert "NET101" in ids
    assert "SEC102" in ids

def test_typescript_scanner(tmp_path: Path):
    ts_code = "axios.get('/api');"
    file_path = tmp_path / "test.ts"
    file_path.write_text(ts_code, encoding="utf-8")
    
    scanner = TypeScriptScanner(file_path, tmp_path)
    findings = scanner.scan()
    
    assert len(findings) == 1
    assert findings[0].id == "NET102"  # axios
