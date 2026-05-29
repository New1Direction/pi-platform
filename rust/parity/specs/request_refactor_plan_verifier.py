"""Parity spec for PiRequestRefactorPlanVerifier.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRequestRefactorPlanVerifier"

_mod = load_py_agent("pi_request_refactor_plan_verifier.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRequestRefactorPlanVerifier()
    out = agent.verify_refactor(_mod.RequestRefactorInput(**data))
    return out.model_dump()


# Complete plan: hits a key from both check groups -> PASSED.
_COMPLETE = (
    "Refactor plan: built a full dependency impact map of affected modules, "
    "and documented the data migration plus the rollout/deploy sequence."
)
# Missing both groups -> two missing_elements.
_MISSING_BOTH = "We will rename a few variables and tidy up some comments."
# Has impact/dependency but no migration/deploy -> one missing element.
_MISSING_MIGRATION = "Completed the dependency analysis and impact assessment of all callers."
# Has migration/deploy but no impact/dependency -> one (other) missing element.
_MISSING_IMPACT = "The migration scripts are ready and the deploy pipeline is configured."
# Case-insensitivity check: uppercase keywords must still match via .lower().
_UPPERCASE = "DEPENDENCY graph done; MIGRATION steps drafted."

SAMPLES = [
    {"input": {"plan_content": _COMPLETE}},
    {"input": {"plan_content": _MISSING_BOTH}},
    {"input": {"plan_content": _MISSING_MIGRATION}},
    {"input": {"plan_content": _MISSING_IMPACT}},
    {"input": {"plan_content": _UPPERCASE}},
    {"input": {"plan_content": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"plan_content": _MISSING_BOTH},
     "env": {"PI_REQUEST_REFACTOR_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"plan_content": _MISSING_BOTH},
     "env": {"PI_REQUEST_REFACTOR_STRICT_MODE": "true"}},
]
