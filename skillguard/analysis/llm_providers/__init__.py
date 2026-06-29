import os
from skillguard.analysis.llm_providers.base_provider import BaseProvider
from skillguard.analysis.llm_providers.gemini_provider import GeminiProvider
from skillguard.analysis.llm_providers.openai_provider import OpenAIProvider
from skillguard.analysis.llm_providers.ollama_provider import OllamaProvider

def get_provider() -> BaseProvider:
    """
    Selects and returns an initialized LLM Provider based on environment variables.
    Priority order:
    1. Explicit SKILLGUARD_PROVIDER environment variable ('gemini', 'openai', 'ollama')
    2. GEMINI_API_KEY set -> GeminiProvider
    3. OPENAI_API_KEY set -> OpenAIProvider
    4. Default -> OllamaProvider
    """
    provider_type = os.environ.get("SKILLGUARD_PROVIDER", "").lower()
    
    if provider_type == "gemini":
        return GeminiProvider()
    elif provider_type == "openai":
        return OpenAIProvider()
    elif provider_type == "ollama":
        return OllamaProvider()
        
    # Auto-detect
    if os.environ.get("GEMINI_API_KEY"):
        return GeminiProvider()
    elif os.environ.get("OPENAI_API_KEY"):
        return OpenAIProvider()
        
    # Default fallback
    return OllamaProvider()

__all__ = [
    "BaseProvider",
    "GeminiProvider",
    "OpenAIProvider",
    "OllamaProvider",
    "get_provider"
]
