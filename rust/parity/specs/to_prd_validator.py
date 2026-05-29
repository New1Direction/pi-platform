"""Parity spec for PiToPrdValidator.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiToPrdValidator"

_mod = load_py_agent("pi_to_prd_validator.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiToPrdValidator()
    out = agent.validate_prd(_mod.ToPrdInput(**data))
    return out.model_dump()


# A complete PRD touching every required section group.
_COMPLETE = "\n".join(
    [
        "# Objective",
        "Deliver a deterministic validator.",
        "## Non-Goals",
        "Out of scope: training models.",
        "## Requirements",
        "The spec defines functional behaviour.",
        "## Verification",
        "Success criteria: all parity tests pass.",
    ]
)

# Missing everything.
_EMPTY_SECTIONS = "Just a paragraph of prose with no headings whatsoever."

# Has objective + requirements only (missing non-goals + verification).
_PARTIAL = "\n".join(
    [
        "Objective: build a thing.",
        "Requirements: it must compile.",
    ]
)

# Only missing the Verification section.
_NO_VERIFICATION = "\n".join(
    [
        "Goal: ship it.",
        "Non-Goal: rewrite the kernel.",
        "Specification: detailed spec follows.",
    ]
)

# Case-insensitivity check: keywords appear only in mixed/upper case.
_MIXED_CASE = "\n".join(
    [
        "OBJECTIVE",
        "OUT OF SCOPE",
        "SPECIFICATION",
        "VALIDATION",
    ]
)

SAMPLES = [
    {"input": {"prd_content": _COMPLETE}},
    {"input": {"prd_content": _EMPTY_SECTIONS}},
    {"input": {"prd_content": _PARTIAL}},
    {"input": {"prd_content": _NO_VERIFICATION}},
    {"input": {"prd_content": _MIXED_CASE}},
    {"input": {"prd_content": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"prd_content": _EMPTY_SECTIONS},
     "env": {"PI_TO_PRD_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"prd_content": _EMPTY_SECTIONS},
     "env": {"PI_TO_PRD_STRICT_MODE": "true"}},
    # env present but not "true" -> treated as non-strict (WARN)
    {"input": {"prd_content": _PARTIAL},
     "env": {"PI_TO_PRD_STRICT_MODE": "0"}},
]
