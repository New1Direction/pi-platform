"""Parity spec for PiGrillMeQuestionnaire.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiGrillMeQuestionnaire"

_mod = load_py_agent("pi_grill_me_questionnaire.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiGrillMeQuestionnaire()
    out = agent.grill_plan(_mod.GrillMeInput(**data))
    return out.model_dump()


_CLEAN = "Build the auth service, write tests, and deploy via the CI pipeline."
_ETC = "Steps: lint, build, test, etc."
_TBD = "Database schema: TBD pending review."
_TODO = "TODO: wire up the metrics exporter."
_PLACEHOLDER = "Set API_KEY to the placeholder value for now."
_IMPL_LATER = "We'll implement later once the spec lands."
_MULTI = "\n".join(
    [
        "Phase 1: scaffold the service (TODO finish handlers).",
        "Phase 2: integrate auth, caching, etc.",
        "Phase 3: a placeholder section, implement later.",
        "Final review: TBD.",
    ]
)
# Word-boundary edge: substrings that should NOT trip \betc\b / \btodo\b.
_BOUNDARY = "We fetched sketches and reviewed the todolist column quietly."

SAMPLES = [
    {"input": {"plan_content": _CLEAN}},
    {"input": {"plan_content": _ETC}},
    {"input": {"plan_content": _TBD}},
    {"input": {"plan_content": _TODO}},
    {"input": {"plan_content": _PLACEHOLDER}},
    {"input": {"plan_content": _IMPL_LATER}},
    {"input": {"plan_content": _MULTI}},
    {"input": {"plan_content": _BOUNDARY}},
    {"input": {"plan_content": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"plan_content": _MULTI},
     "env": {"PI_GRILL_ME_STRICT_MODE": "false"}},
    {"input": {"plan_content": _MULTI},
     "env": {"PI_GRILL_ME_STRICT_MODE": "true"}},
]
