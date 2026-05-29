"""Parity spec for PiZKNonPrimeFieldRangeSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiZKNonPrimeFieldRangeSentry"

_mod = load_py_agent("pi_zk_non_prime_field_range_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiZKNonPrimeFieldRangeSentry()
    out = agent.audit_non_prime_range(_mod.ZKNonPrimeFieldRangeInput(**data))
    return out.model_dump()


# BN254 scalar field prime (r): the >= threshold.
_PRIME = "21888242871839275222246405745257275088548364400416034343698204186575808495617"
_PRIME_MINUS_1 = "21888242871839275222246405745257275088548364400416034343698204186575808495616"

# Clean: only small literals (< 10 digits) and a big-but-below-prime number.
_CLEAN = "\n".join(
    [
        "pragma circom 2.0.0;",
        "template Range() {",
        "    signal input x;",
        "    x <== 123456789;",          # 9 digits -> below the 10-digit floor
        "    signal y <== 1000000000;",  # 10 digits but tiny value -> below prime
        "}",
    ]
)

# The prime itself meets the >= threshold -> flagged.
_OVER_PRIME = f"signal c <== {_PRIME};"

# A value comfortably above the prime (80 nines) -> flagged.
_HUGE = "constant <== " + ("9" * 80) + ";"

# One below the prime -> must NOT be flagged.
_BELOW_PRIME = f"signal c <== {_PRIME_MINUS_1};"

# Word-boundary edge: digits glued to letters have no \b -> not matched.
_EMBEDDED = "var v = abc" + _PRIME + "; // no word boundary before digits"

# Two flagged literals on separate lines (ordering must be preserved).
_MULTI = "\n".join(
    [
        f"a <== {_PRIME};",
        "ok <== 42;",
        "small <== 123456789;",
        "big <== " + ("9" * 80) + ";",
    ]
)

SAMPLES = [
    {"input": {"file_path": "clean.circom", "circom_code": _CLEAN}},
    {"input": {"file_path": "over.circom", "circom_code": _OVER_PRIME}},
    {"input": {"file_path": "huge.circom", "circom_code": _HUGE}},
    {"input": {"file_path": "below.circom", "circom_code": _BELOW_PRIME}},
    {"input": {"file_path": "embedded.circom", "circom_code": _EMBEDDED}},
    {"input": {"file_path": "multi.circom", "circom_code": _MULTI}},
    {"input": {"file_path": "empty.circom", "circom_code": ""}},
    {"input": {"file_path": "lvl.circom", "circom_code": _OVER_PRIME, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "over.circom", "circom_code": _OVER_PRIME},
     "env": {"PI_ZK_NON_PRIME_FIELD_STRICT_MODE": "false"}},
    {"input": {"file_path": "over.circom", "circom_code": _OVER_PRIME},
     "env": {"PI_ZK_NON_PRIME_FIELD_STRICT_MODE": "true"}},
]
