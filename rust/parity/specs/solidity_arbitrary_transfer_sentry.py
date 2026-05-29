"""Parity spec for PiSolidityArbitraryTransferSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityArbitraryTransferSentry"

_mod = load_py_agent("pi_solidity_arbitrary_transfer_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityArbitraryTransferSentry()
    out = agent.audit_arbitrary_transfer(_mod.ArbitraryTransferInput(**data))
    return out.model_dump()


# A clean contract: no address parameter, nothing transferred.
_CLEAN = "function ping(uint256 amount) public { total += amount; }"

# Vulnerable: direct `token.transfer(...)` on a user-supplied address param.
_VULN_DIRECT = (
    "function rug(address token, uint256 amt) public {\n"
    "    token.transfer(msg.sender, amt);\n"
    "}"
)

# Vulnerable: `IERC20(token).transferFrom(...)` path.
_VULN_IERC20 = (
    "function drain(address token, address victim) external {\n"
    "    IERC20(token).transferFrom(victim, address(this), 1000);\n"
    "}"
)

# Vulnerable: `safeTransfer(IERC20(token), ...)` library-style path.
_VULN_SAFETRANSFER = (
    "function sweep(address token) public {\n"
    "    safeTransfer(IERC20(token), msg.sender);\n"
    "}"
)

# Safe: guarded by a whitelist mapping lookup.
_SAFE_WHITELIST = (
    "function pull(address token, uint256 amt) public {\n"
    "    require(whitelist[token]);\n"
    "    IERC20(token).transferFrom(msg.sender, address(this), amt);\n"
    "}"
)

# Safe: guarded by a require(param == trusted) equality check.
_SAFE_REQUIRE_EQ = (
    "function pay(address token, uint256 amt) public {\n"
    "    require(token == trustedToken);\n"
    "    token.transfer(msg.sender, amt);\n"
    "}"
)

# Safe: guarded by an onlyOwner-style modifier mention in the body.
_SAFE_ONLYOWNER = (
    "function adminSweep(address token) public {\n"
    "    onlyOwner();\n"
    "    token.safeTransfer(msg.sender, 1);\n"
    "}"
)

# Multiple functions: one clean, one vulnerable.
_MULTI = (
    "function safeOne(uint256 x) public { y = x; }\n"
    "function rugTwo(address token, uint256 amt) public {\n"
    "    token.transferFrom(msg.sender, address(this), amt);\n"
    "}"
)

# Address param present but nothing transferred -> safe.
_ADDR_NO_TRANSFER = (
    "function note(address who) public {\n"
    "    lastCaller = who;\n"
    "}"
)

SAMPLES = [
    {"input": {"file_path": "C.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_DIRECT}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_IERC20}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_SAFETRANSFER}},
    {"input": {"file_path": "C.sol", "solidity_code": _SAFE_WHITELIST}},
    {"input": {"file_path": "C.sol", "solidity_code": _SAFE_REQUIRE_EQ}},
    {"input": {"file_path": "C.sol", "solidity_code": _SAFE_ONLYOWNER}},
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "C.sol", "solidity_code": _ADDR_NO_TRANSFER}},
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_DIRECT, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_DIRECT},
     "env": {"PI_ARBITRARY_TRANSFER_STRICT_MODE": "false"}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_DIRECT},
     "env": {"PI_ARBITRARY_TRANSFER_STRICT_MODE": "true"}},
]
