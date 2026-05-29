"""Parity spec for PiSolidityERC20TransferRecipientSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityERC20TransferRecipientSentry"

_mod = load_py_agent("pi_solidity_erc20_transfer_recipient_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityERC20TransferRecipientSentry()
    out = agent.audit_transfer_recipient(_mod.ERC20TransferRecipientInput(**data))
    return out.model_dump()


# Clean: transfer recipient validated against address(0) -> PASSED.
_SECURE_TRANSFER = "\n".join(
    [
        "function pay(address to, uint256 amt) public {",
        "    require(to != address(0), \"zero addr\");",
        "    token.transfer(to, amt);",
        "}",
    ]
)

# Vulnerable: transfer with no recipient validation -> flagged.
_UNVALIDATED_TRANSFER = "\n".join(
    [
        "function pay(address to, uint256 amt) public {",
        "    token.transfer(to, amt);",
        "}",
    ]
)

# Vulnerable: transferFrom recipient (2nd param) not validated -> flagged.
_UNVALIDATED_TRANSFERFROM = "\n".join(
    [
        "function move(address from, address to, uint256 amt) external {",
        "    token.transferFrom(from, to, amt);",
        "}",
    ]
)

# Validated transferFrom: recipient checked against address(this) -> PASSED.
_SECURE_TRANSFERFROM = "\n".join(
    [
        "function move(address from, address to, uint256 amt) external {",
        "    require(to != address(this), \"self\");",
        "    token.transferFrom(from, to, amt);",
        "}",
    ]
)

# Validated via 0x0 dead-address check (reversed operand order) -> PASSED.
_SECURE_REVERSED = "\n".join(
    [
        "function pay(address to, uint256 amt) public {",
        "    require(0x0 != to, \"dead\");",
        "    token.transfer(to, amt);",
        "}",
    ]
)

# Multiple functions: one safe, one vulnerable -> only the bad one flagged.
_MULTI = "\n".join(
    [
        "function safePay(address to, uint256 amt) public {",
        "    require(to != address(0), \"zero\");",
        "    token.transfer(to, amt);",
        "}",
        "function badPay(address dest, uint256 amt) public {",
        "    token.transfer(dest, amt);",
        "}",
    ]
)

# No transfer calls at all -> PASSED.
_NO_TRANSFER = "\n".join(
    [
        "function setOwner(address newOwner) public {",
        "    owner = newOwner;",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE_TRANSFER}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNVALIDATED_TRANSFER}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNVALIDATED_TRANSFERFROM}},
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE_TRANSFERFROM}},
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE_REVERSED}},
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "C.sol", "solidity_code": _NO_TRANSFER}},
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNVALIDATED_TRANSFER, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "C.sol", "solidity_code": _UNVALIDATED_TRANSFER},
     "env": {"PI_TRANSFER_RECIPIENT_STRICT_MODE": "false"}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNVALIDATED_TRANSFER},
     "env": {"PI_TRANSFER_RECIPIENT_STRICT_MODE": "true"}},
]
