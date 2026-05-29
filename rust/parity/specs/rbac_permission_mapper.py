"""Parity spec for PiRBACPermissionMapper.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRBACPermissionMapper"

_mod = load_py_agent("pi_rbac_permission_mapper.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRBACPermissionMapper()
    out = agent.map_rbac_permissions(_mod.RBACInput(**data))
    return out.model_dump()


# Clean, least-privilege policy: no wildcards, no escalation.
_CLEAN = (
    '{"Effect": "Allow", "Action": "s3:GetObject", '
    '"Resource": "arn:aws:s3:::my-bucket/*"}'
)
# Wildcard action (JSON style).
_WILDCARD_ACTION = '{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b"}'
# Wildcard action (YAML/lower style).
_WILDCARD_ACTION_YAML = "action: '*'\nresource: arn:aws:s3:::b"
# Wildcard resource WITH an Allow effect -> flagged at 70.
_WILDCARD_RESOURCE = '{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}'
# Wildcard resource WITHOUT any Allow effect -> NOT flagged.
_WILDCARD_RESOURCE_NO_ALLOW = '{"Action": "s3:GetObject", "Resource": "*"}'
# Privilege escalation via iam:PassRole.
_PRIV_ESC = '{"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"}'
# Everything at once: wildcard action + wildcard resource(allow) + escalation.
_ALL_THREE = (
    '{"Effect": "Allow", "Action": "*", "Resource": "*", '
    '"Note": "iam:AttachRolePolicy"}'
)

SAMPLES = [
    {"input": {"policy_file_path": "p.json", "policy_content": _CLEAN}},
    {"input": {"policy_file_path": "p.json", "policy_content": _WILDCARD_ACTION}},
    {"input": {"policy_file_path": "p.yaml", "policy_content": _WILDCARD_ACTION_YAML}},
    {"input": {"policy_file_path": "p.json", "policy_content": _WILDCARD_RESOURCE}},
    {"input": {"policy_file_path": "p.json", "policy_content": _WILDCARD_RESOURCE_NO_ALLOW}},
    {"input": {"policy_file_path": "p.json", "policy_content": _PRIV_ESC}},
    {"input": {"policy_file_path": "p.json", "policy_content": _ALL_THREE}},
    {"input": {"policy_file_path": "p.json", "policy_content": ""}},
    # non-strict env -> WARN path: risk>30 but is_secure stays True.
    {"input": {"policy_file_path": "p.json", "policy_content": _WILDCARD_ACTION},
     "env": {"PI_RBAC_STRICT_MODE": "false"}},
    # explicit strict env -> OVERLY_PERMISSIVE.
    {"input": {"policy_file_path": "p.json", "policy_content": _WILDCARD_ACTION},
     "env": {"PI_RBAC_STRICT_MODE": "true"}},
]
