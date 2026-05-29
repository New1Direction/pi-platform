"""Parity spec for PiZKSignalUnconstrainedConstraint.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZKSignalUnconstrainedConstraint"

_mod = load_py_agent("pi_zk_signal_unconstrained_constraint.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZKSignalUnconstrainedConstraint()
    out = agent.audit_unconstrained_signals(_mod.ZKSignalUnconstrainedInput(**data))
    return out.model_dump()


# A fully constrained template: signal assigned via <-- AND has === constraint.
_SECURE = "template Multiplier() {\n    signal input a;\n    signal output c;\n    c <-- a * a;\n    c === a * a;\n}"

# Assigned via <-- but no matching === constraint anywhere in the body.
_UNCONSTRAINED_LEFT = "template Bad() {\n    signal output out;\n    out <-- in1 + in2;\n}"

# Assigned via --> (other non-constraining operator) without === constraint.
_UNCONSTRAINED_RIGHT = "template Bad2() {\n    signal s;\n    in --> s;\n}"

# Constraint present but as `=== signal` (constraint on the right) -> secure.
_RHS_CONSTRAINT = "template Ok() {\n    signal w;\n    w <-- x * y;\n    x * y === w;\n}"

# Multiple templates: one secure, one vulnerable.
_MIXED = "\n".join(
    [
        "template Safe() {",
        "    signal q;",
        "    q <-- a;",
        "    q === a;",
        "}",
        "template Unsafe() {",
        "    signal r;",
        "    r <-- b;",
        "}",
    ]
)

# Two vulnerable signals inside a single template.
_TWO_VULN = "template Many() {\n    signal m;\n    signal n;\n    m <-- p;\n    n --> q;\n}"

# No template at all -> nothing scanned -> secure.
_NO_TEMPLATE = "pragma circom 2.0.0;\nsignal x;\nx <-- y;"

SAMPLES = [
    {"input": {"file_path": "a.circom", "circom_code": _SECURE}},
    {"input": {"file_path": "a.circom", "circom_code": _UNCONSTRAINED_LEFT}},
    {"input": {"file_path": "a.circom", "circom_code": _UNCONSTRAINED_RIGHT}},
    {"input": {"file_path": "a.circom", "circom_code": _RHS_CONSTRAINT}},
    {"input": {"file_path": "a.circom", "circom_code": _MIXED}},
    {"input": {"file_path": "a.circom", "circom_code": _TWO_VULN}},
    {"input": {"file_path": "a.circom", "circom_code": _NO_TEMPLATE}},
    {"input": {"file_path": "a.circom", "circom_code": ""}},
    {"input": {"file_path": "a.circom", "circom_code": _UNCONSTRAINED_LEFT, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "a.circom", "circom_code": _UNCONSTRAINED_LEFT},
     "env": {"PI_ZK_SIGNAL_UNCONSTRAINED_STRICT_MODE": "false"}},
    {"input": {"file_path": "a.circom", "circom_code": _UNCONSTRAINED_LEFT},
     "env": {"PI_ZK_SIGNAL_UNCONSTRAINED_STRICT_MODE": "true"}},
]
