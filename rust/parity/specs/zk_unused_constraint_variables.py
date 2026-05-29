"""Parity spec for PiZKUnusedConstraintVariables.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZKUnusedConstraintVariables"

_mod = load_py_agent("pi_zk_unused_constraint_variables.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZKUnusedConstraintVariables()
    out = agent.audit_unused_variables(_mod.ZKUnusedConstraintInput(**data))
    return out.model_dump()


# Clean circuit: every declared signal appears in a constraint equation.
_CLEAN = "\n".join(
    [
        "template Adder(n) {",
        "    signal input a;",
        "    signal input b;",
        "    signal output c;",
        "    c <== a + b;",
        "}",
    ]
)

# One signal declared but never used in any constraint statement.
_ONE_UNUSED = "\n".join(
    [
        "template Foo(n) {",
        "    signal input a;",
        "    signal output b;",
        "    signal c;",
        "    b <== a + 1;",
        "}",
    ]
)

# Multiple unused signals, exercising distinct constraint operators.
_MULTI_UNUSED = "\n".join(
    [
        "template Bar() {",
        "    signal input x;",
        "    signal input y;",
        "    signal output z;",
        "    signal extra;",
        "    z === x;",
        "}",
    ]
)

# Two templates: one clean, one with an unused signal.
_TWO_TEMPLATES = "\n".join(
    [
        "template Clean() {",
        "    signal input p;",
        "    signal output q;",
        "    q <== p;",
        "}",
        "template Dirty() {",
        "    signal input m;",
        "    signal output n;",
        "    signal dangling;",
        "    n <== m;",
        "}",
    ]
)

# Uses the ==> operator and a signal substring trap: `ab` must not count as
# usage of `a` (word-boundary check).
_WORD_BOUNDARY = "\n".join(
    [
        "template WB() {",
        "    signal input a;",
        "    signal output ab;",
        "    ab ==> ab;",
        "}",
    ]
)

# No template block at all -> nothing scanned, secure.
_NO_TEMPLATE = "pragma circom 2.0.0;\ninclude \"foo.circom\";"

SAMPLES = [
    {"input": {"file_path": "clean.circom", "circom_code": _CLEAN}},
    {"input": {"file_path": "one.circom", "circom_code": _ONE_UNUSED}},
    {"input": {"file_path": "multi.circom", "circom_code": _MULTI_UNUSED}},
    {"input": {"file_path": "two.circom", "circom_code": _TWO_TEMPLATES}},
    {"input": {"file_path": "wb.circom", "circom_code": _WORD_BOUNDARY}},
    {"input": {"file_path": "none.circom", "circom_code": _NO_TEMPLATE}},
    {"input": {"file_path": "empty.circom", "circom_code": ""}},
    # check_level passthrough does not alter logic, but exercises the field.
    {"input": {"file_path": "one.circom", "circom_code": _ONE_UNUSED, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "one.circom", "circom_code": _ONE_UNUSED},
     "env": {"PI_ZK_UNUSED_CONSTRAINT_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "one.circom", "circom_code": _ONE_UNUSED},
     "env": {"PI_ZK_UNUSED_CONSTRAINT_STRICT_MODE": "true"}},
]
