"""Parity spec for PiRustSolanaAccountDataValidation.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRustSolanaAccountDataValidation"

_mod = load_py_agent("pi_rust_solana_account_data_validation.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRustSolanaAccountDataValidation()
    out = agent.audit_account_data(_mod.SolanaAccountDataInput(**data))
    return out.model_dump()


# No AccountInfo / try_borrow_data / next_account_info at all -> secure / PASSED.
_CLEAN = "fn helper(x: u64) -> u64 { x + 1 }"

# Touches AccountInfo but performs no size/length check -> flagged.
_VULN_ACCOUNTINFO = "fn process(account: &AccountInfo) { let data = account.data.borrow(); }"

# try_borrow_data with no size check -> flagged.
_VULN_BORROW = "fn handler(acc: &AccountInfo) { let data = acc.try_borrow_data()?; }"

# next_account_info with no size check -> flagged.
_VULN_NEXT = "fn run(accounts: &[AccountInfo]) { let acc = next_account_info(iter)?; }"

# AccountInfo + data.len() guard -> size check satisfied, secure.
_SAFE_LEN = "fn process(account: &AccountInfo) { let data = account.try_borrow_data()?; let n = data.len(); }"

# AccountInfo + try_from_slice guard -> secure.
_SAFE_TRY_FROM_SLICE = "fn process(account: &AccountInfo) { let s = State::try_from_slice(&account.data.borrow())?; }"

# AccountInfo + size_of guard -> secure.
_SAFE_SIZE_OF = "fn process(account: &AccountInfo) { let need = size_of::<State>(); next_account_info(iter)?; }"

# AccountInfo + data_len guard -> secure.
_SAFE_DATA_LEN = "fn process(account: &AccountInfo) { let n = account.data_len(); try_borrow_data(); }"

# AccountInfo + assert guard -> secure.
_SAFE_ASSERT = "fn process(account: &AccountInfo) { assert!(account.data.borrow().len() > 0); next_account_info(iter)?; }"

# Multiple methods across newlines: one safe (assert), one vulnerable.
_MULTI = "\n".join(
    [
        "fn safe_one(account: &AccountInfo) {",
        "    assert!(account.lamports() > 0);",
        "    let d = account.try_borrow_data()?;",
        "}",
        "",
        "fn bad_one(account: &AccountInfo) {",
        "    let d = account.try_borrow_data()?;",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "lib.rs", "rust_code": _CLEAN}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_ACCOUNTINFO}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_BORROW}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_NEXT}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_LEN}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_TRY_FROM_SLICE}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_SIZE_OF}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_DATA_LEN}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_ASSERT}},
    {"input": {"file_path": "lib.rs", "rust_code": _MULTI}},
    {"input": {"file_path": "lib.rs", "rust_code": ""}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_BORROW, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_BORROW},
     "env": {"PI_SOLANA_ACCOUNT_DATA_STRICT_MODE": "false"}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_BORROW},
     "env": {"PI_SOLANA_ACCOUNT_DATA_STRICT_MODE": "true"}},
]
