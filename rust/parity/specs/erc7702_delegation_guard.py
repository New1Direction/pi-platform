"""Parity spec for PiERC7702DelegationGuard.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiERC7702DelegationGuard"

_mod = load_py_agent("pi_erc7702_delegation_guard.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiERC7702DelegationGuard()
    out = agent.audit_erc7702_delegation(_mod.ERC7702Input(**data))
    return out.model_dump()


# A clean contract: no delegation/authorize name, no "signature" in body.
_SECURE = (
    "contract Vault {\n"
    "    function transfer(address to, uint256 v) public {\n"
    "        balances[to] += v;\n"
    "    }\n"
    "}"
)

# Vulnerable via function name "delegate" + ecrecover, no nonce anywhere.
_DELEGATE_NO_NONCE = (
    "contract Acct {\n"
    "    function delegateCall(bytes sig) public {\n"
    "        address signer = ecrecover(hash, v, r, s);\n"
    "    }\n"
    "}"
)

# Vulnerable via function name "authorize" + ecrecover, no nonce.
_AUTHORIZE_NO_NONCE = (
    "function authorizeAccount(bytes calldata sig) external {\n"
    "    address a = ecrecover(digest, v, r, s);\n"
    "}"
)

# Vulnerable via "signature" in body + ecrecover, no nonce.
_BODY_SIGNATURE_NO_NONCE = (
    "function verify(bytes data) public {\n"
    "    // recovers the signature\n"
    "    address a = ecrecover(h, v, r, s);\n"
    "}"
)

# Safe: matches the delegate trigger AND has ecrecover, but body contains nonce.
_DELEGATE_WITH_NONCE = (
    "function delegateAuth(bytes sig) public {\n"
    "    uint256 n = nonce;\n"
    "    address a = ecrecover(h, v, r, s);\n"
    "}"
)

# Safe: delegate trigger + ecrecover in body, no body nonce, but the WHOLE file
# contains the word "nonces" (the global guard clause `nonces not in code`).
_DELEGATE_GLOBAL_NONCES = (
    "mapping(address => uint256) public nonces;\n"
    "function delegateAuth(bytes sig) public {\n"
    "    address a = ecrecover(h, v, r, s);\n"
    "}"
)

# Trigger matches but NO ecrecover -> not flagged.
_DELEGATE_NO_ECRECOVER = (
    "function delegateAuth(bytes sig) public {\n"
    "    require(msg.sender == owner);\n"
    "}"
)

# Two vulnerable functions in one file -> ordering / multiplicity check.
_MULTI = (
    "function delegateOne(bytes sig) public {\n"
    "    address a = ecrecover(h, v, r, s);\n"
    "}\n"
    "function authorizeTwo(bytes sig) public {\n"
    "    address b = ecrecover(h2, v2, r2, s2);\n"
    "}"
)

SAMPLES = [
    {"input": {"file_path": "Vault.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "Acct.sol", "solidity_code": _DELEGATE_NO_NONCE}},
    {"input": {"file_path": "Auth.sol", "solidity_code": _AUTHORIZE_NO_NONCE}},
    {"input": {"file_path": "Sig.sol", "solidity_code": _BODY_SIGNATURE_NO_NONCE}},
    {"input": {"file_path": "Nonce.sol", "solidity_code": _DELEGATE_WITH_NONCE}},
    {"input": {"file_path": "Nonces.sol", "solidity_code": _DELEGATE_GLOBAL_NONCES}},
    {"input": {"file_path": "NoRec.sol", "solidity_code": _DELEGATE_NO_ECRECOVER}},
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI}},
    # empty / edge input
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    # check_level override (does not affect logic, but exercises the field)
    {"input": {"file_path": "Acct.sol", "solidity_code": _DELEGATE_NO_NONCE,
               "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Acct.sol", "solidity_code": _DELEGATE_NO_NONCE},
     "env": {"PI_ERC7702_GUARD_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "Acct.sol", "solidity_code": _DELEGATE_NO_NONCE},
     "env": {"PI_ERC7702_GUARD_STRICT_MODE": "true"}},
]
