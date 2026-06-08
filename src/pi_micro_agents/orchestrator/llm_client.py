from __future__ import annotations

import logging
import os

logger = logging.getLogger("pi_llm_client")

# Graceful loading of the openai library
try:
    import openai

    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False


class UnifiedLLMClient:
    """Unified client routing requests either through local FreeLLMAPI or Google Vertex AI."""

    def __init__(self) -> None:
        self.gateway_url = os.getenv("PI_LLM_GATEWAY_URL", "")
        self.default_model = os.getenv("PI_LLM_MODEL", "gemini-1.5-flash")

        api_key = os.getenv("FREE_LLM_API_KEY")
        if self.gateway_url and OPENAI_AVAILABLE and api_key:
            logger.info(f"Initialized UnifiedLLMClient routing to FreeLLMAPI base_url: {self.gateway_url}")
            self.client = openai.OpenAI(base_url=self.gateway_url, api_key=api_key)
        else:
            if self.gateway_url and not api_key:
                logger.warning(
                    "PI_LLM_GATEWAY_URL is set but FREE_LLM_API_KEY is missing — running in simulation mode."
                )
            else:
                logger.info(
                    "Local FreeLLMAPI gateway not active in environment. Running with local deterministic simulations."
                )
            self.client = None

    def generate_completion(self, prompt: str, system_prompt: str = "", model: str | None = None) -> str:
        """Generates standard chat completions utilizing local proxy or fallback configurations."""
        target_model = model or self.default_model

        if self.client:
            try:
                response = self.client.chat.completions.create(
                    model=target_model,
                    messages=[{"role": "system", "content": system_prompt}, {"role": "user", "content": prompt}],
                    temperature=0.2,
                )
                return response.choices[0].message.content or ""
            except Exception as e:
                logger.error(f"FreeLLMAPI routing failed: {e}. Attempting standard fallback.")

        return self._mock_fallback(prompt)

    def _mock_fallback(self, prompt: str) -> str:
        """Safe deterministic mock fallback for local testing when offline or unconfigured."""
        return f"[Deterministic Simulation Mode] Processed consensus query: {prompt[:50]}..."
