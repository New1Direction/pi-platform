"""Parity spec for PiSecretsManagerCompletenessChecker.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSecretsManagerCompletenessChecker"

_mod = load_py_agent("pi_secrets_manager_completeness_checker.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSecretsManagerCompletenessChecker()
    out = agent.check_vault_config(_mod.VaultInput(**data))
    return out.model_dump()


_CLEAN = "rotation: true\npolicy: scoped\nkms_key: custom-cmk-123"
_ROTATION_OFF = "rotation: false\nkms_key: custom"
_ROTATION_DISABLED = "enable_rotation = false"
_WILDCARD_POLICY = 'policy: *\nallow all policies'
_WILDCARD_JSON = '{"policy": "*", "rotation": true}'
_DEFAULT_KMS = "kms_key: default\nrotation: true"
_DEFAULT_ENC = "uses default encryption key\nrotation: true"
_MIXED_CASE = "ROTATION: FALSE\nPOLICY: *\ndefault encryption key"

SAMPLES = [
    # clean / passing input
    {"input": {"vault_config": _CLEAN}},
    # rotation disabled -> risk 70, fails (strict default)
    {"input": {"vault_config": _ROTATION_OFF}},
    # enable_rotation = false variant
    {"input": {"vault_config": _ROTATION_DISABLED}},
    # wildcard policy -> risk 85
    {"input": {"vault_config": _WILDCARD_POLICY}},
    # JSON wildcard policy literal
    {"input": {"vault_config": _WILDCARD_JSON}},
    # default kms key -> risk 50
    {"input": {"vault_config": _DEFAULT_KMS}},
    # default encryption key phrasing -> risk 50
    {"input": {"vault_config": _DEFAULT_ENC}},
    # mixed case hits all three gaps -> risk 85
    {"input": {"vault_config": _MIXED_CASE}},
    # empty / edge input
    {"input": {"vault_config": ""}},
    # non-strict env -> WARN path, is_secure stays True even with gaps
    {"input": {"vault_config": _MIXED_CASE},
     "env": {"PI_VAULT_STRICT_MODE": "false"}},
    # explicit strict env -> FAILED path
    {"input": {"vault_config": _MIXED_CASE},
     "env": {"PI_VAULT_STRICT_MODE": "true"}},
]
