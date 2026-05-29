"""Parity spec for PiRustSolanaMissingSignerAssert.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRustSolanaMissingSignerAssert"

_mod = load_py_agent("pi_rust_solana_missing_signer_assert.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRustSolanaMissingSignerAssert()
    out = agent.audit_missing_signer(_mod.SolanaMissingSignerInput(**data))
    return out.model_dump()


# A clean handler that explicitly asserts the signer -> secure.
_SECURE = "\n".join(
    [
        "pub fn withdraw(ctx: Context, account: AccountInfo) {",
        "    if !account.is_signer {",
        "        return Err(ProgramError::MissingRequiredSignature);",
        "    }",
        "    transfer(account);",
        "}",
    ]
)

# A handler taking AccountInfo with NO signer verification anywhere -> vulnerable.
_MISSING = "\n".join(
    [
        "pub fn withdraw(account: AccountInfo) {",
        "    transfer(account, amount);",
        "}",
    ]
)

# AccountInfo appears only in the args (not body) but no signer check -> vulnerable.
_MISSING_ARG_ONLY = "fn close_acc(a: AccountInfo) { let _ = a.lamports(); }"

# Uses the `Signer` type instead of .is_signer -> secure (matches the 'Signer' guard).
_SIGNER_TYPE = "pub fn init(authority: Signer) { do_init(authority); }"

# Lowercase 'signer' word somewhere in the body -> secure (matches signer-lower guard).
_LOWER_SIGNER = "\n".join(
    [
        "pub fn settle(account: AccountInfo) {",
        "    // ensure the signer was validated upstream",
        "    process(account);",
        "}",
    ]
)

# No AccountInfo at all -> ignored, secure.
_NO_ACCOUNTINFO = "pub fn add(x: u64, y: u64) -> u64 { x + y }"

# Multiple functions: one safe (is_signer), one vulnerable.
_MULTI = "\n".join(
    [
        "use solana_program::account_info::AccountInfo;",
        "",
        "pub fn safe_handler(account: AccountInfo) {",
        "    assert!(account.is_signer);",
        "    do_thing(account);",
        "}",
        "",
        "pub fn unsafe_handler(account: AccountInfo) {",
        "    do_thing(account);",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "lib.rs", "rust_code": _SECURE}},
    {"input": {"file_path": "lib.rs", "rust_code": _MISSING}},
    {"input": {"file_path": "lib.rs", "rust_code": _MISSING_ARG_ONLY}},
    {"input": {"file_path": "lib.rs", "rust_code": _SIGNER_TYPE}},
    {"input": {"file_path": "lib.rs", "rust_code": _LOWER_SIGNER}},
    {"input": {"file_path": "lib.rs", "rust_code": _NO_ACCOUNTINFO}},
    {"input": {"file_path": "lib.rs", "rust_code": _MULTI}},
    {"input": {"file_path": "lib.rs", "rust_code": ""}},
    {"input": {"file_path": "lib.rs", "rust_code": _MISSING, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "lib.rs", "rust_code": _MISSING},
     "env": {"PI_SOLANA_MISSING_SIGNER_STRICT_MODE": "false"}},
    {"input": {"file_path": "lib.rs", "rust_code": _MISSING},
     "env": {"PI_SOLANA_MISSING_SIGNER_STRICT_MODE": "true"}},
]
