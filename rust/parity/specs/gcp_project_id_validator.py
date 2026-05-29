"""Parity spec for PiGCPProjectIDValidator.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}

NOTE: the python module defines is_strict_mode() reading
PI_GCPPROJECTIDVALIDATOR_STRICT_MODE, but execute() never calls it, so the env
var does not affect output. No env-branch samples are needed.
"""
from _util import load_py_agent

RUST_NAME = "PiGCPProjectIDValidator"

_mod = load_py_agent("pi_gcp_project_id_validator.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiGCPProjectIDValidator()
    out = agent.execute(_mod.GCPProjectIDInput(**data))
    return out.model_dump()


SAMPLES = [
    # clean, fully valid project id -> PASS
    {"input": {"project_id": "my-valid-project-1"}},
    # too short -> structural FAIL
    {"input": {"project_id": "abc"}},
    # too long (>30 chars) -> structural FAIL
    {"input": {"project_id": "a" + "b" * 35}},
    # invalid chars + must-start-lowercase (uppercase, underscore, dot, space, quote)
    {"input": {"project_id": "Test_Project.Name X"}},
    # consecutive hyphens
    {"input": {"project_id": "my--project"}},
    # leading hyphen
    {"input": {"project_id": "-myproject"}},
    # trailing hyphen
    {"input": {"project_id": "myproject-"}},
    # all digits -> must contain a letter
    {"input": {"project_id": "123456"}},
    # generic/reserved environment name (valid structurally, strict_naming on) -> WARN
    {"input": {"project_id": "staging"}},
    # generic name with strict_naming disabled -> PASS (no warning)
    {"input": {"project_id": "staging", "strict_naming": False}},
    # empty string edge case
    {"input": {"project_id": ""}},
    # leading hyphen that is also a structural failure combo (consecutive + leading)
    {"input": {"project_id": "--bad--"}},
]
