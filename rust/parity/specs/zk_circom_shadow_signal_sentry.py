"""Parity spec for PiZKCircomShadowSignalSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZKCircomShadowSignalSentry"

_mod = load_py_agent("pi_zk_circom_shadow_signal_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZKCircomShadowSignalSentry()
    out = agent.audit_shadow_signals(_mod.CircomShadowSignalInput(**data))
    return out.model_dump()


# A fully clean template: a local var that collides with nothing.
_CLEAN = "\n".join(
    [
        "template Adder(n) {",
        "    signal input a;",
        "    signal output out;",
        "    var sum = 0;",
        "    out <== a + sum;",
        "}",
    ]
)

# Local var shadows a template parameter.
_SHADOW_PARAM = "\n".join(
    [
        "template Mul(width, depth) {",
        "    signal input a;",
        "    signal output b;",
        "    var width;",
        "}",
    ]
)

# Local var shadows an input/output signal declaration.
_SHADOW_SIGNAL = "\n".join(
    [
        "template Hash() {",
        "    signal input msg;",
        "    signal output digest;",
        "    var digest = 0;",
        "}",
    ]
)

# Two templates: the first clean, the second shadows a parameter.
# Exercises the multi-template scan + \ntemplate body boundary.
_MULTI = "\n".join(
    [
        "template First(k) {",
        "    signal input x;",
        "    var temp = x;",
        "}",
        "template Second(k) {",
        "    signal output y;",
        "    var k;",
        "}",
    ]
)

# A var that shadows both a param and a signal name -> param wins ("template parameter").
_BOTH = "\n".join(
    [
        "template Combo(z) {",
        "    signal input z;",
        "    var z;",
        "}",
    ]
)

# No templates at all -> nothing scanned, secure.
_NO_TEMPLATE = "pragma circom 2.0.0;\n// just a comment, no templates here\n"

# Empty args template with a clean local var.
_EMPTY_ARGS = "template Empty() {\n    signal input s;\n    var counter;\n}"

SAMPLES = [
    {"input": {"file_path": "adder.circom", "circom_code": _CLEAN}},
    {"input": {"file_path": "mul.circom", "circom_code": _SHADOW_PARAM}},
    {"input": {"file_path": "hash.circom", "circom_code": _SHADOW_SIGNAL}},
    {"input": {"file_path": "multi.circom", "circom_code": _MULTI}},
    {"input": {"file_path": "combo.circom", "circom_code": _BOTH}},
    {"input": {"file_path": "none.circom", "circom_code": _NO_TEMPLATE}},
    {"input": {"file_path": "empty.circom", "circom_code": _EMPTY_ARGS}},
    {"input": {"file_path": "edge.circom", "circom_code": ""}},
    {"input": {"file_path": "mul.circom", "circom_code": _SHADOW_PARAM, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "mul.circom", "circom_code": _SHADOW_PARAM},
     "env": {"PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "mul.circom", "circom_code": _SHADOW_PARAM},
     "env": {"PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE": "true"}},
]
