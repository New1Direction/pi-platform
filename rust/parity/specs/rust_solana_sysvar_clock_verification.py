"""Parity spec for PiRustSolanaSysvarClockVerification.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRustSolanaSysvarClockVerification"

_mod = load_py_agent("pi_rust_solana_sysvar_clock_verification.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRustSolanaSysvarClockVerification()
    out = agent.audit_sysvar_clock(_mod.SolanaSysvarClockInput(**data))
    return out.model_dump()


_SECURE = "let x = 5;\nmsg!(\"processing\");"
_CLOCK_GET = "let clock = Clock::get()?;"
_UNIX_TS = "let now = clock.unix_timestamp;"
_CLOCK_NS = "let c = Clock::from_account_info(&info)?;"
_COMMENTS = "\n".join(
    [
        "// Clock::get() referenced in a line comment",
        "/* unix_timestamp in a block comment */",
        "* Clock:: leading-star line",
        "let ok = 42;",
    ]
)
_MULTI = "\n".join(
    [
        "use anchor_lang::prelude::*;",
        "    let clock = Clock::get()?;",
        "let ts = clock.unix_timestamp;",
        "// safe Clock:: comment is skipped",
        "let other = compute(value);",
    ]
)

SAMPLES = [
    # clean / passing input
    {"input": {"file_path": "lib.rs", "rust_code": _SECURE}},
    # Clock::get reference -> flagged
    {"input": {"file_path": "lib.rs", "rust_code": _CLOCK_GET}},
    # unix_timestamp reference -> flagged
    {"input": {"file_path": "lib.rs", "rust_code": _UNIX_TS}},
    # generic Clock:: reference -> flagged
    {"input": {"file_path": "lib.rs", "rust_code": _CLOCK_NS}},
    # comment lines referencing clock are all skipped -> secure
    {"input": {"file_path": "lib.rs", "rust_code": _COMMENTS}},
    # multiple flagged lines mixed with skipped comment + safe code
    {"input": {"file_path": "lib.rs", "rust_code": _MULTI}},
    # empty / edge input
    {"input": {"file_path": "lib.rs", "rust_code": ""}},
    # non-default check_level still scans the same way
    {"input": {"file_path": "lib.rs", "rust_code": _CLOCK_GET, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "lib.rs", "rust_code": _CLOCK_GET},
     "env": {"PI_SOLANA_SYSVAR_CLOCK_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "lib.rs", "rust_code": _CLOCK_GET},
     "env": {"PI_SOLANA_SYSVAR_CLOCK_STRICT_MODE": "true"}},
]
