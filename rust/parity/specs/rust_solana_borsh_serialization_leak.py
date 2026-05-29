"""Parity spec for PiRustSolanaBorshSerializationLeak.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRustSolanaBorshSerializationLeak"

_mod = load_py_agent("pi_rust_solana_borsh_serialization_leak.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRustSolanaBorshSerializationLeak()
    out = agent.audit_borsh_leak(_mod.SolanaBorshLeakInput(**data))
    return out.model_dump()


# A clean struct: no Vec / String, no derive -> secure / PASSED.
_SECURE = "\n".join(
    [
        "#[derive(BorshSerialize)]",
        "pub struct Account {",
        "    amount: u64,",
        "    owner: Pubkey,",
        "}",
    ]
)

# BorshSerialize struct with a Vec field -> flagged.
_VEC = "\n".join(
    [
        "#[derive(BorshSerialize, Debug)]",
        "struct Ledger {",
        "    entries: Vec<u8>,",
        "}",
    ]
)

# AnchorSerialize struct with a String field -> flagged.
_STRING = "\n".join(
    [
        "#[derive(AnchorSerialize)]",
        "pub struct Meta {",
        "    name: String,",
        "}",
    ]
)

# Struct that derives a serializer but has only fixed-size fields -> not flagged.
_FIXED_DERIVE = "\n".join(
    [
        "#[derive(AnchorSerialize, Clone)]",
        "pub struct Config {",
        "    bump: u8,",
        "    authority: Pubkey,",
        "}",
    ]
)

# A struct with Vec but WITHOUT a Borsh/Anchor derive -> the derive regex never
# matches, so nothing is flagged.
_NO_DERIVE = "\n".join(
    [
        "#[derive(Debug)]",
        "struct Plain {",
        "    data: Vec<u8>,",
        "}",
    ]
)

# Multiple structs: one secure, two vulnerable (Vec then String) -> both flagged
# in encounter order.
_MULTI = "\n".join(
    [
        "#[derive(BorshSerialize)]",
        "pub struct Header { version: u8 }",
        "",
        "#[derive(BorshSerialize)]",
        "struct Body {",
        "    payload: Vec<u8>,",
        "}",
        "",
        "#[derive(AnchorSerialize)]",
        "pub struct Footer {",
        "    note: String,",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "lib.rs", "rust_code": _SECURE}},
    {"input": {"file_path": "lib.rs", "rust_code": _VEC}},
    {"input": {"file_path": "lib.rs", "rust_code": _STRING}},
    {"input": {"file_path": "lib.rs", "rust_code": _FIXED_DERIVE}},
    {"input": {"file_path": "lib.rs", "rust_code": _NO_DERIVE}},
    {"input": {"file_path": "lib.rs", "rust_code": _MULTI}},
    {"input": {"file_path": "lib.rs", "rust_code": ""}},
    {"input": {"file_path": "lib.rs", "rust_code": _VEC, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "lib.rs", "rust_code": _STRING},
     "env": {"PI_SOLANA_BORSH_LEAK_STRICT_MODE": "false"}},
    {"input": {"file_path": "lib.rs", "rust_code": _STRING},
     "env": {"PI_SOLANA_BORSH_LEAK_STRICT_MODE": "true"}},
]
