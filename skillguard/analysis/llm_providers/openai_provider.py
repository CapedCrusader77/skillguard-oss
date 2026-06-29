import json
import os
import urllib.request
import urllib.error
from skillguard.analysis.llm_providers.base_provider import BaseProvider
from skillguard.analysis.llm_providers.gemini_provider import clean_json_response

class OpenAIProvider(BaseProvider):
    def analyze(self, claimed_purpose: str, observed_capabilities: dict) -> dict:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OPENAI_API_KEY environment variable is not set.")
            
        prompt = self.make_prompt(claimed_purpose, observed_capabilities)
        url = "https://api.openai.com/v1/chat/completions"
        
        payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "response_format": {"type": "json_object"}
        }
        
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            },
            method="POST"
        )
        
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                resp_data = json.loads(response.read().decode("utf-8"))
                text = resp_data["choices"][0]["message"]["content"]
                cleaned = clean_json_response(text)
                return json.loads(cleaned)
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8") if e.fp else ""
            raise RuntimeError(f"OpenAI API call failed with status {e.code}: {error_body}")
        except Exception as e:
            raise RuntimeError(f"Failed to communicate with OpenAI API: {e}")
