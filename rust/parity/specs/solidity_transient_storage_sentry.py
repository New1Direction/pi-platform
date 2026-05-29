"""Parity spec for PiSolidityTransientStorageSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityTransientStorageSentry"

_mod = load_py_agent("pi_solidity_transient_storage_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityTransientStorageSentry()
    out = agent.audit_transient_storage(_mod.TransientStorageInput(**data))
    return out.model_dump()


# Clean: no assembly, no transient storage at all.
_CLEAN = "function transfer(address to, uint amt) public { balances[to] += amt; }"

# Vulnerable: assembly with tstore but no clear-to-zero.
_VULN_TSTORE = "function lock() external { assembly { tstore(0x01, 1) } }"

# Vulnerable via tload usage, never clears the slot.
_VULN_TLOAD = (
    "function guard() internal {\n"
    "    assembly {\n"
    "        let status := tload(0)\n"
    "        if status { revert(0, 0) }\n"
    "    }\n"
    "}"
)

# Safe: uses transient storage but explicitly clears slot with tstore(slot, 0).
_SAFE_CLEAR = (
    "function release() external {\n"
    "    assembly {\n"
    "        let v := tload(0)\n"
    "        tstore(0, 0)\n"
    "    }\n"
    "}"
)

# Mixed contract: one vulnerable function, one safe (cleared), one irrelevant.
_MIXED = "\n".join(
    [
        "function plain(uint x) public { return x * 2; }",
        "function risky() external { assembly { tstore(slot, 1) } }",
        "function safe() external { assembly { tload(slot) tstore( slot , 0 ) } }",
    ]
)

# assembly present but no tstore/tload at all -> not flagged.
_ASM_NO_TSTORE = "function calc() public { assembly { let r := add(1, 2) } }"

SAMPLES = [
    {"input": {"file_path": "C.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_TSTORE}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_TLOAD}},
    {"input": {"file_path": "C.sol", "solidity_code": _SAFE_CLEAR}},
    {"input": {"file_path": "C.sol", "solidity_code": _MIXED}},
    {"input": {"file_path": "C.sol", "solidity_code": _ASM_NO_TSTORE}},
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_TSTORE, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_TSTORE},
     "env": {"PI_TRANSIENT_STORAGE_STRICT_MODE": "false"}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_TSTORE},
     "env": {"PI_TRANSIENT_STORAGE_STRICT_MODE": "true"}},
]
