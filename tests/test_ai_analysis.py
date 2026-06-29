import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from typer.testing import CliRunner

from skillguard.app import app
from skillguard.analysis.claim_extractor import RuleBasedClaimExtractor
from skillguard.analysis.llm_providers import get_provider, GeminiProvider, OpenAIProvider, OllamaProvider

runner = CliRunner()

def test_pubspec_claim_extraction(tmp_path: Path):
    pubspec = tmp_path / "pubspec.yaml"
    pubspec.write_text("name: my_app\ndescription: \"A Flutter Expense Tracker app.\"\n", encoding="utf-8")
    
    extractor = RuleBasedClaimExtractor()
    claims = extractor.extract_claims(tmp_path)
    
    assert claims.claimed_purpose == "A Flutter Expense Tracker app."

def test_get_provider_selection():
    # Explicit provider selection
    with patch.dict(os.environ, {"SKILLGUARD_PROVIDER": "gemini"}):
        assert isinstance(get_provider(), GeminiProvider)
        
    with patch.dict(os.environ, {"SKILLGUARD_PROVIDER": "openai"}):
        assert isinstance(get_provider(), OpenAIProvider)
        
    with patch.dict(os.environ, {"SKILLGUARD_PROVIDER": "ollama"}):
        assert isinstance(get_provider(), OllamaProvider)

    # Auto-detect selection
    with patch.dict(os.environ, {"SKILLGUARD_PROVIDER": "", "GEMINI_API_KEY": "fake_gemini_key"}):
        assert isinstance(get_provider(), GeminiProvider)

    with patch.dict(os.environ, {"SKILLGUARD_PROVIDER": "", "GEMINI_API_KEY": "", "OPENAI_API_KEY": "fake_openai_key"}):
        assert isinstance(get_provider(), OpenAIProvider)
        
    # Default selection
    with patch.dict(os.environ, {"SKILLGUARD_PROVIDER": "", "GEMINI_API_KEY": "", "OPENAI_API_KEY": ""}):
        assert isinstance(get_provider(), OllamaProvider)

@patch("urllib.request.urlopen")
def test_gemini_provider_analyze(mock_urlopen):
    # Mock HTTP response
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "candidates": [{
            "content": {
                "parts": [{
                    "text": '{"assessment": ["Filesystem access is not expected for a weather service."], "trust_impact": -25, "verdict": "REVIEW REQUIRED"}'
                }]
            }
        }]
    }).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp
    
    provider = GeminiProvider()
    with patch.dict(os.environ, {"GEMINI_API_KEY": "fake_key"}):
        res = provider.analyze("Weather MCP Server", {"Filesystem Access": True})
        
    assert res["verdict"] == "REVIEW REQUIRED"
    assert res["trust_impact"] == -25
    assert "Filesystem access is not expected" in res["assessment"][0]

@patch("urllib.request.urlopen")
def test_openai_provider_analyze(mock_urlopen):
    # Mock HTTP response
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "choices": [{
            "message": {
                "content": '{"assessment": ["Filesystem access is not expected for a weather service."], "trust_impact": -25, "verdict": "REVIEW REQUIRED"}'
            }
        }]
    }).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp
    
    provider = OpenAIProvider()
    with patch.dict(os.environ, {"OPENAI_API_KEY": "fake_key"}):
        res = provider.analyze("Weather MCP Server", {"Filesystem Access": True})
        
    assert res["verdict"] == "REVIEW REQUIRED"
    assert res["trust_impact"] == -25

@patch("urllib.request.urlopen")
def test_ollama_provider_analyze(mock_urlopen):
    # Mock HTTP response
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps({
        "response": '{"assessment": ["Filesystem access is not expected for a weather service."], "trust_impact": -25, "verdict": "REVIEW REQUIRED"}'
    }).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_resp
    
    provider = OllamaProvider()
    res = provider.analyze("Weather MCP Server", {"Filesystem Access": True})
        
    assert res["verdict"] == "REVIEW REQUIRED"
    assert res["trust_impact"] == -25

@patch("skillguard.analysis.llm_providers.get_provider")
@patch("skillguard.app.get_scan_targets")
@patch("skillguard.core.repository_discovery.discover_files")
@patch("skillguard.app.group_files_by_repository")
def test_cli_scan_with_ai(mock_group_files, mock_discover_files, mock_get_scan_targets, mock_get_provider, tmp_path):
    # Prepare dummy files
    py_file = tmp_path / "main.py"
    py_file.write_text("import os\nos.system('dir')\n", encoding="utf-8")
    
    readme = tmp_path / "README.md"
    readme.write_text("Weather MCP Server\n", encoding="utf-8")
    
    # Mock LLM provider response
    mock_provider = MagicMock()
    mock_provider.analyze.return_value = {
        "assessment": [
            "Filesystem access is not expected for a weather service.",
            "Command execution capability exceeds stated functionality."
        ],
        "trust_impact": -25,
        "verdict": "REVIEW REQUIRED"
    }
    mock_get_provider.return_value = mock_provider
    
    mock_get_scan_targets.return_value = ([py_file], {"Python": 1}, 1)
    mock_discover_files.return_value = ([py_file], set(), set())
    mock_group_files.return_value = {tmp_path: [py_file]}
    
    result = runner.invoke(app, ["scan", str(tmp_path), "--ai"])
    
    assert result.exit_code == 0
    assert "Claimed Purpose:" in result.stdout
    assert "Weather MCP Server" in result.stdout
    assert "AI Assessment:" in result.stdout
    assert "Filesystem access is not expected for a weather service." in result.stdout
    assert "Command execution capability exceeds stated functionality." in result.stdout
    assert "Trust Impact:" in result.stdout
    assert "-25" in result.stdout
    assert "Verdict:" in result.stdout
    assert "REVIEW REQUIRED" in result.stdout
