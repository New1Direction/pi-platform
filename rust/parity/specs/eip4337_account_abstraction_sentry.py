"""Parity spec for PiEIP4337AccountAbstractionSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiEIP4337AccountAbstractionSentry"

_mod = load_py_agent("pi_eip4337_account_abstraction_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiEIP4337AccountAbstractionSentry()
    out = agent.audit_account_abstraction(_mod.AccountAbstractionInput(**data))
    return out.model_dump()


# A clean Smart Account validation function with no forbidden global access.
_SECURE = (
    "contract Account {\n"
    "  function validateUserOp(UserOp calldata op, bytes32 h, uint256 m) "
    "external returns (uint256) {\n"
    "    require(op.signature.length == 65);\n"
    "    return 0;\n"
    "  }\n"
    "}\n"
)

# validateUserOp reaching for tx.origin (forbidden).
_TX_ORIGIN = (
    "function validateUserOp(UserOp op) external returns (uint256) {\n"
    "  require(tx.origin == owner);\n"
    "  return 0;\n"
    "}\n"
)

# Paymaster validation touching block.timestamp (forbidden).
_BLOCK_TIMESTAMP = (
    "function validatePaymasterUserOp(UserOp op, bytes32 h, uint256 m) "
    "external returns (bytes memory, uint256) {\n"
    "  if (block.timestamp > deadline) revert();\n"
    "}\n"
)

# block.number forbidden access.
_BLOCK_NUMBER = (
    "function validateUserOp(UserOp op) external {\n"
    "  uint256 n = block.number;\n"
    "}\n"
)

# gasleft() forbidden access.
_GASLEFT = (
    "function validateUserOp(UserOp op) external {\n"
    "  uint256 g = gasleft();\n"
    "}\n"
)

# block.blockhash forbidden access.
_BLOCKHASH = (
    "function validatePaymasterUserOp(UserOp op) external {\n"
    "  bytes32 b = block.blockhash;\n"
    "}\n"
)

# Multiple forbidden accesses in one validation function -> multiple findings,
# plus a non-validation function that should be ignored entirely.
_MULTI = (
    "contract Mix {\n"
    "  function validateUserOp(UserOp op) external returns (uint256) {\n"
    "    require(tx.origin == owner);\n"
    "    uint256 ts = block.timestamp;\n"
    "    uint256 n = block.number;\n"
    "    return 0;\n"
    "  }\n"
    "  function helper() public { uint256 x = gasleft(); }\n"
    "}\n"
)

# Forbidden access but inside a NON-validation function -> should pass clean.
_FORBIDDEN_NON_VALIDATION = (
    "function transfer(address to) public {\n"
    "  require(tx.origin == msg.sender);\n"
    "  uint256 t = block.timestamp;\n"
    "}\n"
)

SAMPLES = [
    {"input": {"file_path": "Account.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "Account.sol", "solidity_code": _TX_ORIGIN}},
    {"input": {"file_path": "Paymaster.sol", "solidity_code": _BLOCK_TIMESTAMP}},
    {"input": {"file_path": "Account.sol", "solidity_code": _BLOCK_NUMBER}},
    {"input": {"file_path": "Account.sol", "solidity_code": _GASLEFT}},
    {"input": {"file_path": "Paymaster.sol", "solidity_code": _BLOCKHASH}},
    {"input": {"file_path": "Mix.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Token.sol", "solidity_code": _FORBIDDEN_NON_VALIDATION}},
    # empty / edge input
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Account.sol", "solidity_code": _TX_ORIGIN,
               "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Account.sol", "solidity_code": _TX_ORIGIN},
     "env": {"PI_AA_SENTRY_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "Account.sol", "solidity_code": _TX_ORIGIN},
     "env": {"PI_AA_SENTRY_STRICT_MODE": "true"}},
]
