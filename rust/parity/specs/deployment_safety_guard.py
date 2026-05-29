"""Parity spec for PiDeploymentSafetyGuard.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDeploymentSafetyGuard"

_mod = load_py_agent("pi_deployment_safety_guard.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDeploymentSafetyGuard()
    out = agent.verify_deployment_safety(_mod.DeploymentSafetyInput(**data))
    return out.model_dump()


_CLEAN = "def add(a, b):\n    return a + b"
_TODO = "# TODO: finish wiring the handler\nx = compute()"
_FIXME = "result = compute()  # FIXME before shipping"
_PLACEHOLDER = "config = PLACEHOLDER_VALUE  # swap later"
_SYNTAXERR = "Traceback: SyntaxError: invalid syntax on line 3"
_NOT_DEFINED = "NameError: name 'foo' is not defined"
# Placeholder branch must win over the syntax-error branch (first if).
_BOTH = "TODO: fix the SyntaxError that NameError 'x' is not defined raises"

SAMPLES = [
    # clean / passing input -> DEPLOYED_SUCCESSFULLY
    {"input": {"deployment_target": "production", "post_remediation_code": _CLEAN}},
    # TODO placeholder path -> risk 75
    {"input": {"deployment_target": "staging", "post_remediation_code": _TODO}},
    # FIXME placeholder path -> risk 75
    {"input": {"deployment_target": "staging", "post_remediation_code": _FIXME}},
    # "placeholder" (case-insensitive) path -> risk 75
    {"input": {"deployment_target": "prod", "post_remediation_code": _PLACEHOLDER}},
    # syntaxerror path -> risk 90
    {"input": {"deployment_target": "prod", "post_remediation_code": _SYNTAXERR}},
    # "not defined" path -> risk 90
    {"input": {"deployment_target": "prod", "post_remediation_code": _NOT_DEFINED}},
    # both branches match -> first (placeholder) wins, risk 75
    {"input": {"deployment_target": "prod", "post_remediation_code": _BOTH}},
    # empty / edge input + explicit health_check_endpoint override
    {"input": {"deployment_target": "", "post_remediation_code": "",
               "health_check_endpoint": "http://10.0.0.1:9000/healthz"}},
    # env var is read by is_strict_mode() but NEVER used by verify_deployment_safety,
    # so these two exercise both env branches and MUST yield identical output.
    {"input": {"deployment_target": "prod", "post_remediation_code": _TODO},
     "env": {"PI_DEPLOYMENT_SAFETY_STRICT_MODE": "false"}},
    {"input": {"deployment_target": "prod", "post_remediation_code": _TODO},
     "env": {"PI_DEPLOYMENT_SAFETY_STRICT_MODE": "true"}},
]
