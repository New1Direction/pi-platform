"""Parity spec for PiDataRetentionPolicyEnforcer.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDataRetentionPolicyEnforcer"

_mod = load_py_agent("pi_data_retention_policy_enforcer.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDataRetentionPolicyEnforcer()
    out = agent.enforce_retention(_mod.RetentionInput(**data))
    return out.model_dump()


_CLEAN = "retention: 30d\ndelete: scheduled\npurge: enabled\nconsent_check: true"
_INDEFINITE = "retain: indefinite\nlifecycle: none"
_DELETE_NEVER = "policy:\n  delete: never\n  archive: cold-storage"
_UNLIMITED = "RETENTION: UNLIMITED\nbackups: kept"
_PII_NO_CONSENT = "pii: retain\nconsent_check: false"
_PERSONAL_SAVE = "personal_data: save\nconsent: false"
_PII_WITH_CONSENT = "pii: retain\nconsent_check: true"

SAMPLES = [
    # clean / passing policy
    {"input": {"policy_content": _CLEAN}},
    # indefinite retention -> risk 80, fails in strict mode
    {"input": {"policy_content": _INDEFINITE}},
    # delete: never variant
    {"input": {"policy_content": _DELETE_NEVER}},
    # retention: unlimited variant (uppercase, exercises .lower())
    {"input": {"policy_content": _UNLIMITED}},
    # PII retained without consent -> risk 90
    {"input": {"policy_content": _PII_NO_CONSENT}},
    # personal_data save without consent -> risk 90
    {"input": {"policy_content": _PERSONAL_SAVE}},
    # PII present but consent check passes -> no issue, secure
    {"input": {"policy_content": _PII_WITH_CONSENT}},
    # empty / edge input
    {"input": {"policy_content": ""}},
    # non-strict env -> WARN path, is_secure stays True despite risk
    {"input": {"policy_content": _INDEFINITE},
     "env": {"PI_RETENTION_STRICT_MODE": "false"}},
    # explicit strict env -> FAILED_COMPLIANCE
    {"input": {"policy_content": _INDEFINITE},
     "env": {"PI_RETENTION_STRICT_MODE": "true"}},
]
