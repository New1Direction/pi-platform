"""Parity spec for PiSolidityERC20SafeApproveAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityERC20SafeApproveAuditor"

_mod = load_py_agent("pi_solidity_erc20_safe_approve_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityERC20SafeApproveAuditor()
    out = agent.audit_safe_approve(_mod.ERC20SafeApproveInput(**data))
    return out.model_dump()


# Clean / passing: uses SafeERC20 safeApprove.
_SAFE = (
    "contract Vault {\n"
    "    function deposit(address token, address spender, uint amount) public {\n"
    "        IERC20(token).safeApprove(spender, amount);\n"
    "    }\n"
    "}"
)

# Single vulnerable direct approve.
_DIRECT = (
    "contract Vault {\n"
    "    function approveAll(address spender, uint amount) public {\n"
    "        token.approve(spender, amount);\n"
    "    }\n"
    "}"
)

# Multiple functions: one safe, one vulnerable.
_MIXED = (
    "function safeOne(address s, uint a) public {\n"
    "    erc20.safeApprove(s, a);\n"
    "}\n"
    "function badOne(address s, uint a) public {\n"
    "    erc20.approve(s, a);\n"
    "}"
)

# Two vulnerable approve calls in one body -> only first flagged (break).
_TWO_IN_ONE = (
    "function doubleApprove(address s) public {\n"
    "    usdt.approve(s, 0);\n"
    "    usdt.approve(s, type(uint).max);\n"
    "}"
)

# Vulnerable call with whitespace before the paren: token.approve (a, b).
_SPACED = (
    "function spaced(address s, uint a) external {\n"
    "    token.approve (s, a);\n"
    "}"
)

# No functions at all (only state / comments).
_NO_FUNCS = (
    "contract Empty {\n"
    "    uint256 public total;\n"
    "    // token.approve(spender, amount) in a comment\n"
    "}"
)

SAMPLES = [
    {"input": {"file_path": "Vault.sol", "solidity_code": _SAFE}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _DIRECT}},
    {"input": {"file_path": "Mixed.sol", "solidity_code": _MIXED}},
    {"input": {"file_path": "Double.sol", "solidity_code": _TWO_IN_ONE}},
    {"input": {"file_path": "Spaced.sol", "solidity_code": _SPACED}},
    {"input": {"file_path": "Empty.sol", "solidity_code": _NO_FUNCS}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _DIRECT, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Vault.sol", "solidity_code": _DIRECT},
     "env": {"PI_ERC20_SAFE_APPROVE_STRICT_MODE": "false"}},
    # strict env -> REJECTED path
    {"input": {"file_path": "Vault.sol", "solidity_code": _DIRECT},
     "env": {"PI_ERC20_SAFE_APPROVE_STRICT_MODE": "true"}},
]
