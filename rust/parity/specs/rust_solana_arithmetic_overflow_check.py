"""Parity spec for PiRustSolanaArithmeticOverflowCheck.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRustSolanaArithmeticOverflowCheck"

_mod = load_py_agent("pi_rust_solana_arithmetic_overflow_check.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRustSolanaArithmeticOverflowCheck()
    out = agent.audit_arithmetic_overflow(_mod.SolanaArithmeticOverflowInput(**data))
    return out.model_dump()


# A clean line that uses a checked wrapper -> secure.
_SAFE = "let total = ctx.amount.checked_add(fee).ok_or(Error::Overflow)?;"
# Each distinct raw operator triggers a flag (each surrounded by spaces).
_ADD = "let total = a + b;"
_SUB = "let total = a - b;"
_MUL = "let total = a * b;"
_DIV = "let total = a / b;"
# A "safe" keyword on the same line suppresses the flag even with a raw op.
_SAFE_KEYWORD = "saturating_value = a + b;"
# Comment lines are skipped (//, /*, *).
_COMMENTS = "\n".join(
    [
        "// let bad = a + b;",
        "/* let bad = c - d; */",
        "* doc-style continuation a * b",
        "let safe = a.checked_mul(b).unwrap();",
    ]
)
# Mixed file: comment skipped, one safe line, two flagged lines.
_MULTI = "\n".join(
    [
        "// SPDX comment with a + b inside",
        "let ok = balance.checked_sub(amount)?;",
        "let bad1 = a + b;",
        "    let bad2 = total / count;  ",
        "let macro_only = foo!();",
    ]
)

SAMPLES = [
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE}},
    {"input": {"file_path": "lib.rs", "rust_code": _ADD}},
    {"input": {"file_path": "lib.rs", "rust_code": _SUB}},
    {"input": {"file_path": "lib.rs", "rust_code": _MUL}},
    {"input": {"file_path": "lib.rs", "rust_code": _DIV}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_KEYWORD}},
    {"input": {"file_path": "lib.rs", "rust_code": _COMMENTS}},
    {"input": {"file_path": "lib.rs", "rust_code": _MULTI}},
    {"input": {"file_path": "lib.rs", "rust_code": ""}},
    {"input": {"file_path": "lib.rs", "rust_code": _ADD, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "lib.rs", "rust_code": _ADD},
     "env": {"PI_SOLANA_ARITHMETIC_OVERFLOW_STRICT_MODE": "false"}},
    {"input": {"file_path": "lib.rs", "rust_code": _ADD},
     "env": {"PI_SOLANA_ARITHMETIC_OVERFLOW_STRICT_MODE": "true"}},
]
