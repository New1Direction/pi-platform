"""Parity spec for PiLLMContextWindowDriftSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiLLMContextWindowDriftSentry"

_mod = load_py_agent("pi_llm_context_window_drift_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiLLMContextWindowDriftSentry()
    out = agent.audit_context_drift(_mod.LLMContextWindowDriftInput(**data))
    return out.model_dump()


# A clean, short prompt -> PASSED.
_CLEAN = "Please summarize the following document in three concise bullet points."

# Oversized prompt (> 80000 chars) -> size finding.
_OVERSIZED = "a" * 80001

# Exactly at the boundary (not > 80000) -> still passes the size check.
_BOUNDARY = "b" * 80000

# Excessive token redundancy: 1002 repeats of "tok " => 1001 redundant matches,
# which is > 1000 -> redundancy finding (stays under the 80000 size limit at
# 4008 chars).
_REDUNDANT = "tok " * 1002

# Just under the redundancy threshold: 1001 repeats => 1000 redundant matches,
# which is NOT > 1000 -> passes.
_REDUNDANT_UNDER = "tok " * 1001

SAMPLES = [
    # clean / passing
    {"input": {"prompt": _CLEAN}},
    # empty edge input
    {"input": {"prompt": ""}},
    # oversized -> size drift finding (strict default)
    {"input": {"prompt": _OVERSIZED}},
    # exactly at boundary -> passes
    {"input": {"prompt": _BOUNDARY}},
    # excessive redundancy -> redundancy finding
    {"input": {"prompt": _REDUNDANT}},
    # just under redundancy threshold -> passes
    {"input": {"prompt": _REDUNDANT_UNDER}},
    # check_level field carried but unused by logic
    {"input": {"prompt": _CLEAN, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"prompt": _OVERSIZED},
     "env": {"PI_LLM_CONTEXT_WINDOW_DRIFT_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"prompt": _OVERSIZED},
     "env": {"PI_LLM_CONTEXT_WINDOW_DRIFT_STRICT_MODE": "true"}},
    # non-strict env on the redundancy path
    {"input": {"prompt": _REDUNDANT},
     "env": {"PI_LLM_CONTEXT_WINDOW_DRIFT_STRICT_MODE": "False"}},
]
