import json
import os
import urllib.request
import urllib.error
from skillguard.analysis.llm_providers.base_provider import BaseProvider
from skillguard.analysis.llm_providers.gemini_provider import clean_json_response

class OllamaProvider(BaseProvider):
    def analyze(self, claimed_purpose: str, observed_capabilities: dict) -> dict:
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
        model = os.environ.get("OLLAMA_MODEL", "llama3")
        
        prompt = self.make_prompt(claimed_purpose, observed_capabilities)
        url = f"{host}/api/generate"
        
        payload = {
            "model": model,
            "prompt": prompt,
            "format": "json",
            "stream": False
        }
        
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                resp_data = json.loads(response.read().decode("utf-8"))
                text = resp_data["response"]
                cleaned = clean_json_response(text)
                return json.loads(cleaned)
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8") if e.fp else ""
            raise RuntimeError(f"Ollama API call failed with status {e.code}: {error_body}")
        except Exception as e:
            raise RuntimeError(f"Failed to communicate with local Ollama server at {host}: {e}")
