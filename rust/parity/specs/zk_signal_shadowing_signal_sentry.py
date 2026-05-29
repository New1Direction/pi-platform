"""Parity spec for PiZKSignalShadowingSignalSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZKSignalShadowingSignalSentry"

_mod = load_py_agent("pi_zk_signal_shadowing_signal_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZKSignalShadowingSignalSentry()
    out = agent.audit_signal_shadowing(_mod.ZKSignalShadowingInput(**data))
    return out.model_dump()


# A clean template with no duplicate signal declarations.
_CLEAN = "template Adder() {\n    signal input a;\n    signal input b;\n    signal output c;\n    c <== a + b;\n}"

# Duplicate signal name within a single template (input then output, same name).
_DUP_INOUT = "template Bad() {\n    signal input x;\n    signal output x;\n}"

# Plain duplicate (no input/output qualifier) declared twice.
_DUP_PLAIN = "template Dup() {\n    signal y;\n    signal z;\n    signal y;\n}"

# Multiple distinct templates, only the second one has a shadowed signal.
_MULTI = "\n".join(
    [
        "template Ok(n) {",
        "    signal input a;",
        "    signal output b;",
        "}",
        "template Shadow() {",
        "    signal input s;",
        "    signal s;",
        "}",
    ]
)

# Same signal declared three times in one template -> flagged twice.
_TRIPLE = "template Triple() {\n    signal input v;\n    signal v;\n    signal v;\n}"

# Code with no template blocks at all.
_NO_TEMPLATE = "pragma circom 2.0.0;\nsignal input loose;"

SAMPLES = [
    {"input": {"file_path": "clean.circom", "circom_code": _CLEAN}},
    {"input": {"file_path": "bad.circom", "circom_code": _DUP_INOUT}},
    {"input": {"file_path": "dup.circom", "circom_code": _DUP_PLAIN}},
    {"input": {"file_path": "multi.circom", "circom_code": _MULTI}},
    {"input": {"file_path": "triple.circom", "circom_code": _TRIPLE}},
    {"input": {"file_path": "none.circom", "circom_code": _NO_TEMPLATE}},
    {"input": {"file_path": "empty.circom", "circom_code": ""}},
    {"input": {"file_path": "bad.circom", "circom_code": _DUP_INOUT, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "bad.circom", "circom_code": _DUP_INOUT},
     "env": {"PI_ZK_SIGNAL_SHADOWING_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "bad.circom", "circom_code": _DUP_INOUT},
     "env": {"PI_ZK_SIGNAL_SHADOWING_STRICT_MODE": "true"}},
]
