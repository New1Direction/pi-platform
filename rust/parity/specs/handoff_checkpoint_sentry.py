"""Parity spec for PiHandoffCheckpointSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiHandoffCheckpointSentry"

_mod = load_py_agent("pi_handoff_checkpoint_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiHandoffCheckpointSentry()
    out = agent.audit_handoff(_mod.HandoffInput(**data))
    return out.model_dump()


# A clean, fully-complete handoff (all three keywords present).
_COMPLETE = (
    "Status: branch feature/x is ready.\n"
    "Reproduction: run `pytest tests/`.\n"
    "Next step: open a PR and request review."
)
# Missing only the reproduction keyword.
_MISSING_REPRO = "Status: in progress. Next step: write the migration."
# Missing only the "next step" keyword.
_MISSING_NEXT = "Reproduction: see script.sh. Status: green."
# Missing only the status keyword.
_MISSING_STATUS = "Reproduction: pytest. Next step: deploy to staging."
# Missing everything.
_MISSING_ALL = "Just some unrelated notes about the weather."
# Keyword matching is case-insensitive and substring-based: "REPRODUCTION"
# (upper), "next steps" (contains "next step"), "statuses" (contains "status").
_CASE_AND_SUBSTRING = "REPRODUCTION done. Next steps below. Current statuses logged."

SAMPLES = [
    # Clean / passing.
    {"input": {"handoff_content": _COMPLETE}},
    # Each distinct flagged path (one keyword missing at a time).
    {"input": {"handoff_content": _MISSING_REPRO}},
    {"input": {"handoff_content": _MISSING_NEXT}},
    {"input": {"handoff_content": _MISSING_STATUS}},
    # All missing.
    {"input": {"handoff_content": _MISSING_ALL}},
    # Empty input (edge): everything missing.
    {"input": {"handoff_content": ""}},
    # Case-insensitive + substring matching all pass.
    {"input": {"handoff_content": _CASE_AND_SUBSTRING}},
    # Env var branches: non-strict -> WARN path, is_secure coerced True.
    {"input": {"handoff_content": _MISSING_ALL},
     "env": {"PI_HANDOFF_STRICT_MODE": "false"}},
    # Env var branches: strict -> REJECTED path.
    {"input": {"handoff_content": _MISSING_ALL},
     "env": {"PI_HANDOFF_STRICT_MODE": "true"}},
]
