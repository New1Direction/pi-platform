"""Parity spec for PiZKCircomUnderconstrainedSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}

PARITY CAVEAT: the original Python agent derives the audited signal set via
  ``assigned_signals = set(left_assigns + right_assigns)``  (source line 63)
and then builds ``vulnerable_signals`` / ``flagged_findings`` by iterating that
set. CPython set iteration order is governed by per-process hash randomization
(``PYTHONHASHSEED``), so the ordering of those two fields is NON-DETERMINISTIC
across runs whenever a single template contributes more than one vulnerable
signal, and cannot be byte-matched by any deterministic Rust port. The Rust port
deduplicates preserving first-seen insertion order. We therefore declare
``NORMALIZE`` for those fields so they are compared as order-insensitive sets —
testing the real contract, not a hash accident. See the agent's `deviations`.
"""
from _util import load_py_agent

RUST_NAME = "PiZKCircomUnderconstrainedSentry"

_mod = load_py_agent("pi_zk_circom_underconstrained_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZKCircomUnderconstrainedSentry()
    out = agent.audit_circom_constraints(_mod.CircomUnderconstrainedInput(**data))
    return out.model_dump()


# A fully constrained signal: `out <-- a` paired with `out === a` -> secure.
_CLEAN = "\n".join([
    "template Secure(n) {",
    "    signal input a;",
    "    signal output out;",
    "    out <-- a + 1;",
    "    out === a + 1;",
    "}",
])

# Left-assign `<--` with no `===` -> single vulnerable signal (deterministic).
_LEFT = "\n".join([
    "template LeftBad() {",
    "    out <-- a * b;",
    "}",
])

# Right-assign `-->` with no `===` -> single vulnerable signal (deterministic).
_RIGHT = "\n".join([
    "template RightBad() {",
    "    in --> result;",
    "}",
])

# Two templates: one secure, one underconstrained. Single bad signal -> stable.
_MULTI_TEMPLATE = "\n".join([
    "template Good() {",
    "    y <-- x;",
    "    y === x;",
    "}",
    "template Bad() {",
    "    z <-- w;",
    "}",
])

# Inline `template` keyword mid-line is swallowed into the previous body, so only
# one template (Outer) is detected; it owns two underconstrained signals (a, z).
# (>1 signal in one template -> ORDER MAY FLAKE, hence NORMALIZE.)
_INLINE = "template Outer() {\n a <-- 1; template Inner() { z <-- 9; }\n}"

# No templates at all -> nothing to scan -> secure.
_NO_TEMPLATE = "pragma circom 2.0.0;\n// just a comment\nsignal x;"

SAMPLES = [
    # clean / passing input
    {"input": {"file_path": "secure.circom", "circom_code": _CLEAN}},
    # left-assign underconstrained path
    {"input": {"file_path": "left.circom", "circom_code": _LEFT}},
    # right-assign underconstrained path
    {"input": {"file_path": "right.circom", "circom_code": _RIGHT}},
    # mixed: one secure template + one underconstrained template
    {"input": {"file_path": "multi.circom", "circom_code": _MULTI_TEMPLATE}},
    # inline keyword swallow -> two signals in one template (order may flake)
    {"input": {"file_path": "inline.circom", "circom_code": _INLINE}},
    # no templates
    {"input": {"file_path": "none.circom", "circom_code": _NO_TEMPLATE}},
    # empty edge input
    {"input": {"file_path": "empty.circom", "circom_code": ""}},
    # non-strict check_level field (still STRICT via env/config default)
    {"input": {"file_path": "left.circom", "circom_code": _LEFT, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "left.circom", "circom_code": _LEFT},
     "env": {"PI_CIRCOM_UNDERCONSTRAINED_STRICT_MODE": "false"}},
    # strict env explicitly true -> REJECTED, is_secure False
    {"input": {"file_path": "left.circom", "circom_code": _LEFT},
     "env": {"PI_CIRCOM_UNDERCONSTRAINED_STRICT_MODE": "true"}},
]

# `set(...)`-derived fields (source line 63); order is hash-randomized in CPython.
NORMALIZE = ["vulnerable_signals", "flagged_findings"]
