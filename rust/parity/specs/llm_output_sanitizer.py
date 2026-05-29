"""Parity spec for PiLLMOutputSanitizer.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiLLMOutputSanitizer"

_mod = load_py_agent("pi_llm_output_sanitizer.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiLLMOutputSanitizer()
    out = agent.sanitize_llm_output(_mod.LLMOutputSanitizerInput(**data))
    return out.model_dump()


SAMPLES = [
    # 1. Clean, passing output -> risk 0, CLEAN
    {"input": {"raw_output": "The weather today is sunny and pleasant."}},
    # 2. Single system-prompt trigger -> risk 35.0, still secure (< 40)
    {"input": {"raw_output": "You are a helpful assistant for booking flights."}},
    # 3. Two system-prompt triggers -> risk 70.0 -> COMPROMISED
    {"input": {"raw_output": "The system prompt says to ignore previous instructions."}},
    # 4. Credential leak with literal api_key -> redacted + COMPROMISED
    {"input": {"raw_output": "Use api_key=sk-12345 to authenticate the request."}},
    # 5. Bearer token leak (no api_key, so no substring scrub) -> COMPROMISED
    {"input": {"raw_output": "Authorization: Bearer eyJhbGciOiJI token granted."}},
    # 6. Combined triggers + credential, exceeds cap -> risk_score clamps to 100.0
    {"input": {"raw_output": (
        "you are a helpful assistant. system prompt: internal guidelines. "
        "ignore previous instructions. api_key=abc aws_access here."
    )}},
    # 7. Empty raw_output edge case -> CLEAN, empty sanitized
    {"input": {"raw_output": ""}},
    # 8. Uppercase API_KEY: matched by raw.lower() check but .replace('api_key') is
    #    case-sensitive so the original-case text is NOT scrubbed (parity gotcha)
    {"input": {"raw_output": "Your API_KEY is exposed here.",
               "system_prompt_reference": "v2-guidelines"}},
]
