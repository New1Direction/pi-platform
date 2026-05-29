"""Parity spec for PiZKDivByZeroConstraintAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZKDivByZeroConstraintAuditor"

_mod = load_py_agent("pi_zk_div_by_zero_constraint_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZKDivByZeroConstraintAuditor()
    out = agent.audit_div_by_zero(_mod.ZKDivByZeroConstraintInput(**data))
    return out.model_dump()


# Clean: division guarded by an explicit `!== 0` constraint.
_SECURE = "template Bar() { c <== x / y; y !== 0; }"
# Vulnerable: division with no non-zero constraint on the divisor.
_VULN = "\n".join(
    [
        "template Foo(n) {",
        "  signal input a;",
        "  signal b;",
        "  b <== a / divisor;",
        "}",
    ]
)
# Guarded via assert(divisor != 0) (matches the second constraint regex).
_ASSERT_GUARD = "template Baz() { c <== x / y; assert(y != 0); }"
# Backslash division operator path.
_BACKSLASH = "template Quux() { z <== p \\ q; }"
# Multiple templates: one secure, one vulnerable.
_MULTI = "\n".join(
    [
        "template Safe() { out <== a / b; b !== 0; }",
        "template Unsafe() { out <== m / n; }",
    ]
)
# Two unguarded divisions in the same template -> two findings.
_TWO_DIVS = "template Dbl() { x <== a / b; y <== c / d; }"
# No template wrapper -> division is never scanned (regex requires a template).
_NO_TEMPLATE = "signal out; out <== a / b;"

SAMPLES = [
    {"input": {"file_path": "a.circom", "circom_code": _SECURE}},
    {"input": {"file_path": "a.circom", "circom_code": _VULN}},
    {"input": {"file_path": "a.circom", "circom_code": _ASSERT_GUARD}},
    {"input": {"file_path": "a.circom", "circom_code": _BACKSLASH}},
    {"input": {"file_path": "a.circom", "circom_code": _MULTI}},
    {"input": {"file_path": "a.circom", "circom_code": _TWO_DIVS}},
    {"input": {"file_path": "a.circom", "circom_code": _NO_TEMPLATE}},
    {"input": {"file_path": "a.circom", "circom_code": ""}},
    # explicit check_level override (unused by logic, but a valid field)
    {"input": {"file_path": "a.circom", "circom_code": _VULN, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "a.circom", "circom_code": _VULN},
     "env": {"PI_ZK_DIV_BY_ZERO_STRICT_MODE": "false"}},
    {"input": {"file_path": "a.circom", "circom_code": _VULN},
     "env": {"PI_ZK_DIV_BY_ZERO_STRICT_MODE": "true"}},
]
