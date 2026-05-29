"""Parity spec for PiZKCircomDivisionSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZKCircomDivisionSentry"

_mod = load_py_agent("pi_zk_circom_division_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZKCircomDivisionSentry()
    out = agent.audit_circom_division(_mod.ZKCircomDivisionInput(**data))
    return out.model_dump()


# Clean: divisor explicitly constrained non-zero via assert(... != 0)
_CLEAN_ASSERT = "\n".join(
    [
        "template SafeDiv() {",
        "  signal input a;",
        "  signal input c;",
        "  signal output b;",
        "  b <-- a / c;",
        "  assert(c != 0);",
        "}",
    ]
)

# Clean: divisor constrained via `c !== 0`
_CLEAN_NEQ = "\n".join(
    [
        "template SafeDiv2() {",
        "  d <-- e / f;",
        "  f !== 0;",
        "}",
    ]
)

# Clean: divisor handled via `c === 0` zero-check block
_CLEAN_EQQ = "\n".join(
    [
        "template SafeDiv3() {",
        "  g <-- h / k;",
        "  k === 0;",
        "}",
    ]
)

# Vulnerable: unconstrained division using `<--`
_VULN_ARROW = "\n".join(
    [
        "template Vuln() {",
        "  signal input num;",
        "  signal input den;",
        "  out <-- num / den;",
        "}",
    ]
)

# Vulnerable: division via `=` and backslash divisor token
_VULN_EQ_BACKSLASH = "\n".join(
    [
        "template VulnEq() {",
        "  result = numerator \\ denom;",
        "}",
    ]
)

# Vulnerable: division via `-->` operator direction
_VULN_RARROW = "\n".join(
    [
        "template VulnR() {",
        "  z --> y / w;",
        "}",
    ]
)

# Multiple templates: one safe, one vulnerable
_MIXED = "\n".join(
    [
        "template OK() {",
        "  a <-- b / c;",
        "  assert(c != 0);",
        "}",
        "template Bad() {",
        "  p <-- q / r;",
        "}",
    ]
)

# No template at all -> no findings
_NO_TEMPLATE = "signal input a;\nb <-- a / c;\n"

SAMPLES = [
    {"input": {"file_path": "ok.circom", "circom_code": _CLEAN_ASSERT}},
    {"input": {"file_path": "ok2.circom", "circom_code": _CLEAN_NEQ}},
    {"input": {"file_path": "ok3.circom", "circom_code": _CLEAN_EQQ}},
    {"input": {"file_path": "v1.circom", "circom_code": _VULN_ARROW}},
    {"input": {"file_path": "v2.circom", "circom_code": _VULN_EQ_BACKSLASH}},
    {"input": {"file_path": "v3.circom", "circom_code": _VULN_RARROW}},
    {"input": {"file_path": "mixed.circom", "circom_code": _MIXED}},
    {"input": {"file_path": "none.circom", "circom_code": _NO_TEMPLATE}},
    {"input": {"file_path": "empty.circom", "circom_code": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "v1.circom", "circom_code": _VULN_ARROW},
     "env": {"PI_CIRCOM_DIVISION_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "v1.circom", "circom_code": _VULN_ARROW},
     "env": {"PI_CIRCOM_DIVISION_STRICT_MODE": "true"}},
]
