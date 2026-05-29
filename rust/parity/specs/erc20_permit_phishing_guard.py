"""Parity spec for PiERC20PermitPhishingGuard.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiERC20PermitPhishingGuard"

_mod = load_py_agent("pi_erc20_permit_phishing_guard.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiERC20PermitPhishingGuard()
    out = agent.audit_permit(_mod.PermitGuardInput(**data))
    return out.model_dump()


# Single vulnerable function: permit() with a user-controlled `owner`.
_VULN = (
    "function gaslessApprove(address owner, uint256 value, uint8 v, bytes32 r, bytes32 s) "
    "external { token.permit(owner, address(this), value, deadline, v, r, s); }"
)

# Safe: permit() locked to msg.sender.
_SAFE = (
    "function selfPermit(uint256 value, uint8 v, bytes32 r, bytes32 s) external "
    "{ token.permit(msg.sender, address(this), value, deadline, v, r, s); }"
)

# No permit() call at all.
_NOPERMIT = "function transfer(address to, uint256 amt) public { balances[to] += amt; }"

# Multi-function contract with nested braces, mixing safe + vulnerable + plain.
_MULTI = "\n".join(
    [
        "pragma solidity ^0.8.0;",
        "contract Vault {",
        "    function deposit(uint256 amount) public {",
        "        require(amount > 0);",
        "        balances[msg.sender] += amount;",
        "    }",
        "",
        "    function gaslessDeposit(address owner, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {",
        "        if (amount > 0) {",
        "            token.permit(owner, address(this), amount, deadline, v, r, s);",
        "        }",
        "        token.transferFrom(owner, address(this), amount);",
        "    }",
        "",
        "    function selfPermit(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {",
        "        token.permit(msg.sender, address(this), amount, deadline, v, r, s);",
        "    }",
        "}",
    ]
)

# Whitespace stress: extra spaces around `.permit (` and `msg . sender` does NOT
# match (the regex requires `msg.sender`), so this stays vulnerable.
_SPACEY = (
    "function spaceyPermit(address owner) external "
    "{ token .permit ( owner , a , b ); }"
)

# Two vulnerable functions -> both reported, order preserved.
_TWO_VULN = (
    "function aPermit(address ownerA) external { erc20.permit(ownerA, x, y); }\n"
    "function bPermit(address ownerB) external { erc20.permit(ownerB, x, y); }"
)

SAMPLES = [
    {"input": {"file_path": "Clean.sol", "solidity_code": _SAFE}},
    {"input": {"file_path": "Vuln.sol", "solidity_code": _VULN}},
    {"input": {"file_path": "Plain.sol", "solidity_code": _NOPERMIT}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Spacey.sol", "solidity_code": _SPACEY}},
    {"input": {"file_path": "Two.sol", "solidity_code": _TWO_VULN}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Vuln.sol", "solidity_code": _VULN, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Vuln.sol", "solidity_code": _VULN},
     "env": {"PI_PERMIT_GUARD_STRICT_MODE": "false"}},
    # strict env -> REJECTED path
    {"input": {"file_path": "Vuln.sol", "solidity_code": _VULN},
     "env": {"PI_PERMIT_GUARD_STRICT_MODE": "true"}},
]
