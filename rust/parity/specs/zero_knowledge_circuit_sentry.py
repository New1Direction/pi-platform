"""Parity spec for PiZeroKnowledgeCircuitSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZeroKnowledgeCircuitSentry"

_mod = load_py_agent("pi_zero_knowledge_circuit_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZeroKnowledgeCircuitSentry()
    out = agent.audit_zk_circuit(_mod.ZKCircuitInput(**data))
    return out.model_dump()


# Clean / passing: every signal assigned with <-- is also constrained with ===.
_SECURE = "\n".join(
    [
        "template Multiplier() {",
        "  signal input a;",
        "  signal input b;",
        "  signal output out;",
        "  out <-- a * b;",
        "  out === a * b;",
        "}",
    ]
)

# Vulnerable: `out` assigned with <-- but never constrained with ===.
_UNDER_CONSTRAINED = "\n".join(
    [
        "template Bad() {",
        "  signal input a;",
        "  signal output out;",
        "  out <-- a * a;",
        "}",
    ]
)

# Vulnerable via the --> operator instead of <--.
_RIGHT_ARROW = "\n".join(
    [
        "template RightArrow() {",
        "  signal input a;",
        "  signal output out;",
        "  a * a --> out;",
        "}",
    ]
)

# Multiple distinct vulnerable signals in one template.
_MULTI_VULN = "\n".join(
    [
        "template MultiVuln() {",
        "  signal input a;",
        "  signal output x;",
        "  signal output y;",
        "  x <-- a;",
        "  y <-- a + 1;",
        "}",
    ]
)

# Two templates: one secure, one vulnerable.
_TWO_TEMPLATES = "\n".join(
    [
        "template Safe() {",
        "  signal output s;",
        "  s <-- 1;",
        "  s === 1;",
        "}",
        "template Unsafe() {",
        "  signal output u;",
        "  u <-- 2;",
        "}",
    ]
)

# Same signal flagged once even though it is assigned twice (dedup path).
_DUP_SIGNAL = "\n".join(
    [
        "template Dup() {",
        "  signal output z;",
        "  z <-- 1;",
        "  z <-- 2;",
        "}",
    ]
)

# No templates at all -> empty findings, secure.
_NO_TEMPLATE = "pragma circom 2.0.0;\n// just a comment, no template here"

SAMPLES = [
    {"input": {"file_path": "ok.circom", "circom_code": _SECURE}},
    {"input": {"file_path": "bad.circom", "circom_code": _UNDER_CONSTRAINED}},
    {"input": {"file_path": "arrow.circom", "circom_code": _RIGHT_ARROW}},
    {"input": {"file_path": "multi.circom", "circom_code": _MULTI_VULN}},
    {"input": {"file_path": "two.circom", "circom_code": _TWO_TEMPLATES}},
    {"input": {"file_path": "dup.circom", "circom_code": _DUP_SIGNAL}},
    {"input": {"file_path": "none.circom", "circom_code": _NO_TEMPLATE}},
    {"input": {"file_path": "empty.circom", "circom_code": ""}},
    {"input": {"file_path": "lvl.circom", "circom_code": _UNDER_CONSTRAINED, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "bad.circom", "circom_code": _UNDER_CONSTRAINED},
     "env": {"PI_ZK_CIRCUIT_STRICT_MODE": "false"}},
    {"input": {"file_path": "bad.circom", "circom_code": _UNDER_CONSTRAINED},
     "env": {"PI_ZK_CIRCUIT_STRICT_MODE": "true"}},
]
