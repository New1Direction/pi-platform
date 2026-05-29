"""Parity spec for PiToIssuesBreakdown.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiToIssuesBreakdown"

_mod = load_py_agent("pi_to_issues_breakdown.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiToIssuesBreakdown()
    out = agent.breakdown_issues(_mod.ToIssuesInput(**data))
    return out.model_dump()


# Clean spec: has acceptance criteria + checklist items -> PASSED
_CLEAN = "\n".join(
    [
        "## Plan",
        "Acceptance Criteria:",
        "- [ ] Build the parser",
        "- [ ] Wire the router",
    ]
)

# Numbered tasks path: "Task N: ..." extraction
_NUMBERED = "acceptance criteria are below. Task 1: Implement login. Task 2: Add logout."

# Plain dash list path: "- word words"
_DASH = "\n".join(
    [
        "Criteria for done:",
        "- alpha task",
        "- beta_task here",
    ]
)

# Missing acceptance criteria AND no items -> two errors, REJECTED
_NO_CRITERIA_NO_ITEMS = "Just a paragraph of prose with nothing actionable to extract"

# Has items but NO criteria -> single error -> REJECTED
_ITEMS_NO_CRITERIA = "- [ ] Do the thing\n- [ ] Do another thing"

# Reserved title filtering ("checklist" / "acceptance criteria" excluded) + dedup
_RESERVED = "\n".join(
    [
        "Acceptance Criteria",
        "- Checklist",
        "- [ ] real work item",
        "- [ ] real work item",
    ]
)

# Empty spec: strip() empty so no "no items" error, only missing-criteria error
_EMPTY = ""

# Whitespace-only spec: strip() empty -> only missing-criteria error
_BLANK = "   \n\t  "

SAMPLES = [
    {"input": {"spec_content": _CLEAN}},
    {"input": {"spec_content": _NUMBERED}},
    {"input": {"spec_content": _DASH}},
    {"input": {"spec_content": _NO_CRITERIA_NO_ITEMS}},
    {"input": {"spec_content": _ITEMS_NO_CRITERIA}},
    {"input": {"spec_content": _RESERVED}},
    {"input": {"spec_content": _EMPTY}},
    {"input": {"spec_content": _BLANK}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"spec_content": _NO_CRITERIA_NO_ITEMS},
     "env": {"PI_TO_ISSUES_STRICT_MODE": "false"}},
    {"input": {"spec_content": _NO_CRITERIA_NO_ITEMS},
     "env": {"PI_TO_ISSUES_STRICT_MODE": "true"}},
]
