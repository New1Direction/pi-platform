"""
Real Ollama client for local model calls.

This is the actual implementation behind the LOCAL tiers.
It calls Ollama's REST API and returns real token usage.
"""

from typing import Any, Dict, Optional

import requests


class OllamaClient:
    """Minimal client for Ollama with real token reporting."""

    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url.rstrip("/")

    def generate(
        self,
        model: str,
        prompt: str,
        system: Optional[str] = None,
        options: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """
        Call Ollama and return the response + real token counts.
        """
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
        }
        if system:
            payload["system"] = system
        if options:
            payload["options"] = options

        resp = requests.post(f"{self.base_url}/api/generate", json=payload, timeout=120)
        resp.raise_for_status()
        data = resp.json()

        # Ollama returns these fields with real token counts
        return {
            "response": data.get("response", ""),
            "model": data.get("model"),
            "prompt_eval_count": data.get("prompt_eval_count", 0),  # input tokens
            "eval_count": data.get("eval_count", 0),  # output tokens
            "total_tokens": data.get("prompt_eval_count", 0) + data.get("eval_count", 0),
            "done": data.get("done", False),
        }

    def is_available(self) -> bool:
        """Quick health check."""
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return r.status_code == 200
        except Exception:
            return False


# Best practical defaults for local tiers (as of 2026)
DEFAULT_LOCAL_LIGHT_MODEL = "qwen2.5:1.5b"  # Fast, low resource, good at structured tasks
DEFAULT_LOCAL_MEDIUM_MODEL = "qwen2.5:7b"  # Strong quality/cost balance for moderate work
