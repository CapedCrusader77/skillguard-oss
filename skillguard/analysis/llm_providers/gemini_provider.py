import json
import os
import urllib.request
import urllib.error
from skillguard.analysis.llm_providers.base_provider import BaseProvider

def clean_json_response(text: str) -> str:
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()

class GeminiProvider(BaseProvider):
    def analyze(self, claimed_purpose: str, observed_capabilities: dict) -> dict:
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY environment variable is not set.")
            
        prompt = self.make_prompt(claimed_purpose, observed_capabilities)
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "responseMimeType": "application/json"
            }
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
                text = resp_data["candidates"][0]["content"]["parts"][0]["text"]
                cleaned = clean_json_response(text)
                return json.loads(cleaned)
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8") if e.fp else ""
            raise RuntimeError(f"Gemini API call failed with status {e.code}: {error_body}")
        except Exception as e:
            raise RuntimeError(f"Failed to communicate with Gemini API: {e}")
