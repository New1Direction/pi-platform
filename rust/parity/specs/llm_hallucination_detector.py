"""Parity spec for PiLLMHallucinationDetector.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiLLMHallucinationDetector"

_mod = load_py_agent("pi_llm_hallucination_detector.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiLLMHallucinationDetector()
    out = agent.audit_hallucination(_mod.HallucinationDetectorInput(**data))
    return out.model_dump()


# A clean response with no contradictions.
_CLEAN = "The system is secure and passed all checks with no vulnerabilities found."
# Case 1: asserts secure AND insecure in the same envelope.
_CONTRADICT_SEC = "The endpoint is secure, yet the same module is vulnerable to spoofing."
# Case 1 via other synonyms (clean/passed + danger/unsafe/rejected).
_CONTRADICT_SEC2 = "Audit passed cleanly, but the config is unsafe and the request was rejected."
# Case 2: claims full compliance while listing failures.
_CONTRADICT_COMP = "The deployment is fully compliant, however two validation checks failed."
# Case 2 via 100% coverage + non-compliant.
_CONTRADICT_COMP2 = "Tests report 100% coverage even though the schema is non-compliant."
# Both cases triggered at once -> two flagged findings, two vulnerable entries.
_BOTH = (
    "The release is secure and fully compliant; nonetheless it is vulnerable "
    "and several checks failed with violations found."
)
# Neutral text matching neither side.
_NEUTRAL = "The weather report indicates a mild afternoon with light winds."

SAMPLES = [
    # Clean, passing input (secure -> PASSED regardless of strict mode).
    {"input": {"prompt": "ctx", "response": _CLEAN}},
    # Neutral / empty-ish edge inputs.
    {"input": {"prompt": "ctx", "response": _NEUTRAL}},
    {"input": {"prompt": "", "response": ""}},
    # Case 1 contradiction, strict mode -> REJECTED_HALLUCINATION.
    {"input": {"prompt": "ctx", "response": _CONTRADICT_SEC},
     "env": {"PI_HALLUCINATION_STRICT_MODE": "true"}},
    # Case 1 contradiction, alternate synonyms, strict mode.
    {"input": {"prompt": "ctx", "response": _CONTRADICT_SEC2},
     "env": {"PI_HALLUCINATION_STRICT_MODE": "true"}},
    # Case 1 contradiction, lenient mode -> WARN_HALLUCINATION, is_secure coerced True.
    {"input": {"prompt": "ctx", "response": _CONTRADICT_SEC},
     "env": {"PI_HALLUCINATION_STRICT_MODE": "false"}},
    # Case 2 compliance contradiction, strict mode.
    {"input": {"prompt": "ctx", "response": _CONTRADICT_COMP},
     "env": {"PI_HALLUCINATION_STRICT_MODE": "true"}},
    # Case 2 alternate synonyms, lenient mode -> WARN.
    {"input": {"prompt": "ctx", "response": _CONTRADICT_COMP2},
     "env": {"PI_HALLUCINATION_STRICT_MODE": "false"}},
    # Both cases triggered, strict mode -> two findings.
    {"input": {"prompt": "ctx", "response": _BOTH, "check_level": "MEDIUM"},
     "env": {"PI_HALLUCINATION_STRICT_MODE": "true"}},
]
