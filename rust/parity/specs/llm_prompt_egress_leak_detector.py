"""Parity spec for PiLLMPromptEgressLeakDetector.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiLLMPromptEgressLeakDetector"

_mod = load_py_agent("pi_llm_prompt_egress_leak_detector.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiLLMPromptEgressLeakDetector()
    out = agent.audit_egress_leak(_mod.LLMPromptEgressLeakInput(**data))
    return out.model_dump()


_CLEAN = "Sure, here is a friendly poem about autumn leaves and warm tea."
_AWS = "Your access key is AKIAIOSFODNN7EXAMPLE, keep it safe."
_PRIVKEY = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg...\n"
_SECRET = "Set the api_key header and pass bearer abc123_token-XYZ to the endpoint."
_CC = "Charge it to card 4111111111111 right now."
_SSN = "His social is 123-45-6789 according to the form."
_MULTI = (
    "Here is the AWS key AKIAIOSFODNN7EXAMPLE and his ssn 123-45-6789 "
    "plus an api-key value."
)

SAMPLES = [
    {"input": {"prompt": _CLEAN}},
    {"input": {"prompt": _AWS}},
    {"input": {"prompt": _PRIVKEY}},
    {"input": {"prompt": _SECRET}},
    {"input": {"prompt": _CC}},
    {"input": {"prompt": _SSN}},
    {"input": {"prompt": _MULTI}},
    {"input": {"prompt": ""}},
    {"input": {"prompt": _CLEAN, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"prompt": _AWS},
     "env": {"PI_LLM_PROMPT_EGRESS_LEAK_STRICT_MODE": "false"}},
    {"input": {"prompt": _AWS},
     "env": {"PI_LLM_PROMPT_EGRESS_LEAK_STRICT_MODE": "true"}},
]
