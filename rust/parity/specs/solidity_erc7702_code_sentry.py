"""Parity spec for PiSolidityERC7702CodeSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityERC7702CodeSentry"

_mod = load_py_agent("pi_solidity_erc7702_code_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityERC7702CodeSentry()
    out = agent.audit_erc7702_code(_mod.ERC7702CodeInput(**data))
    return out.model_dump()


# Clean: no delegation-related markers at all -> PASSED.
_SECURE = "function safe(uint256 x) public { uint256 y = x + 1; }"

# Unvalidated delegate parameter, body sets authorized -> flagged.
_UNVALIDATED_DELEGATE = (
    "function setDelegate(address delegateTarget) public { authorized = true; }"
)

# 'delegate' substring in args triggers the branch; param matches 'target'.
_TARGET_PARAM = (
    "function configure(address newTarget) public { "
    "delegation = newTarget; }"
)

# Whitelist validation present -> not flagged (secure).
_WHITELIST_OK = (
    "function setDelegate(address delegateTarget) public { "
    "require(whitelist[delegateTarget], 'bad'); authorized = true; }"
)

# extcodesize validation present -> not flagged (secure).
_EXTCODESIZE_OK = (
    "function setDelegate(address delegateTarget) public { "
    "uint256 s; assembly { s := extcodesize(delegateTarget) } "
    "require(s > 0); authorized = true; }"
)

# Multiple functions: one vulnerable, one safe.
_MULTI = "\n".join(
    [
        "contract C {",
        "  function safeFn(uint256 a) public { uint256 b = a; }",
        "  function riskyFn(address targetAddr) public { authorized = true; }",
        "  function guardedFn(address delegatePtr) public { require(trusted[delegatePtr]); }",
        "}",
    ]
)

# Body mentions 'delegation' / 'authorized' but no address param -> not flagged.
_NO_ADDRESS_PARAM = (
    "function touch(uint256 n) public { authorized = false; delegation = n; }"
)

SAMPLES = [
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNVALIDATED_DELEGATE}},
    {"input": {"file_path": "C.sol", "solidity_code": _TARGET_PARAM}},
    {"input": {"file_path": "C.sol", "solidity_code": _WHITELIST_OK}},
    {"input": {"file_path": "C.sol", "solidity_code": _EXTCODESIZE_OK}},
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "C.sol", "solidity_code": _NO_ADDRESS_PARAM}},
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNVALIDATED_DELEGATE,
               "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _UNVALIDATED_DELEGATE},
     "env": {"PI_ERC7702_CODE_STRICT_MODE": "false"}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNVALIDATED_DELEGATE},
     "env": {"PI_ERC7702_CODE_STRICT_MODE": "true"}},
]
