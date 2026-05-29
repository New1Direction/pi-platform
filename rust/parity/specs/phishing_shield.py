"""Parity spec for PiPhishingShield.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiPhishingShield"

_mod = load_py_agent("pi_phishing_shield.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiPhishingShield()
    out = agent.audit_phishing(_mod.PhishingShieldInput(**data))
    return out.model_dump()


# --- Sample Solidity snippets -------------------------------------------------

# Clean: ordinary view function, no callback / permit semantics.
_CLEAN = (
    "function totalSupply() public view returns (uint256) {\n"
    "    return _totalSupply;\n"
    "}"
)

# Vulnerable Mode 1: onTokenTransfer callback touches msg.sender with no
# require(/revert( gate -> flagged + added to vulnerable_functions.
_VULN_ONTOKENTRANSFER = (
    "function onTokenTransfer(address from, uint256 amount) external {\n"
    "    balances[msg.sender] += amount;\n"
    "}"
)

# Vulnerable Mode 1: tokensReceived variant of the same path.
_VULN_TOKENSRECEIVED = (
    "function tokensReceived(address operator, address from, uint256 amt) external {\n"
    "    lastSender = msg.sender;\n"
    "}"
)

# Safe Mode 1: callback name but msg.sender is guarded by require( -> not flagged.
_SAFE_CALLBACK_REQUIRE = (
    "function onTokenTransfer(address from, uint256 amount) external {\n"
    "    require(msg.sender == address(token), \"bad caller\");\n"
    "    balances[from] += amount;\n"
    "}"
)

# Safe Mode 1: callback name but no msg.sender reference at all -> not flagged.
_SAFE_CALLBACK_NO_SENDER = (
    "function onTokenTransfer(address from, uint256 amount) external {\n"
    "    balances[from] += amount;\n"
    "}"
)

# Mode 2 permit warning: 'deadline' param but no block.timestamp/now check.
# Warning is appended to flagged_findings but NOT to vulnerable_functions, so
# the contract remains is_secure=True / PASSED.
_PERMIT_WARN = (
    "function permit(address owner, address spender, uint256 deadline) external {\n"
    "    _approve(owner, spender, value);\n"
    "}"
)

# Mode 2 permit safe: deadline IS validated against block.timestamp -> no warn.
_PERMIT_SAFE = (
    "function permit(address owner, address spender, uint256 deadline) external {\n"
    "    require(block.timestamp <= deadline, \"expired\");\n"
    "    _approve(owner, spender, value);\n"
    "}"
)

# Comment-stripping edge: the require( gate lives in a // line comment and a
# block /* */ comment, so after stripping the body has msg.sender with no real
# guard -> still flagged (exercises re.sub line + DOTALL block comment removal).
_VULN_COMMENTED_GUARD = (
    "function onTokenTransfer(address from, uint256 amt) external {\n"
    "    // require(msg.sender == token);\n"
    "    /* revert(\"x\"); */\n"
    "    credited[msg.sender] = amt;\n"
    "}"
)

# Declaration-only / interface signature: semicolon appears before any brace, so
# extract_solidity_functions skips it entirely (no body) -> nothing flagged.
_DECL_ONLY = "function onTokenTransfer(address from, uint256 amount) external returns (bool);"

# Multiple functions: one clean, one vulnerable callback, one permit warning.
_MULTI = (
    "function name() public view returns (string memory) { return _name; }\n"
    "function onTokenTransfer(address from, uint256 amt) external {\n"
    "    routed[msg.sender] = amt;\n"
    "}\n"
    "function permit(address owner, uint256 deadline) external {\n"
    "    _approve(owner, value);\n"
    "}"
)


SAMPLES = [
    {"input": {"file_path": "Token.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "Token.sol", "solidity_code": _VULN_ONTOKENTRANSFER}},
    {"input": {"file_path": "Token.sol", "solidity_code": _VULN_TOKENSRECEIVED}},
    {"input": {"file_path": "Token.sol", "solidity_code": _SAFE_CALLBACK_REQUIRE}},
    {"input": {"file_path": "Token.sol", "solidity_code": _SAFE_CALLBACK_NO_SENDER}},
    {"input": {"file_path": "Token.sol", "solidity_code": _PERMIT_WARN}},
    {"input": {"file_path": "Token.sol", "solidity_code": _PERMIT_SAFE}},
    {"input": {"file_path": "Token.sol", "solidity_code": _VULN_COMMENTED_GUARD}},
    {"input": {"file_path": "Token.sol", "solidity_code": _DECL_ONLY}},
    {"input": {"file_path": "Token.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Token.sol", "solidity_code": ""}},
    {"input": {"file_path": "Token.sol", "solidity_code": _VULN_ONTOKENTRANSFER, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Token.sol", "solidity_code": _VULN_ONTOKENTRANSFER},
     "env": {"PI_PHISHING_STRICT_MODE": "false"}},
    {"input": {"file_path": "Token.sol", "solidity_code": _VULN_ONTOKENTRANSFER},
     "env": {"PI_PHISHING_STRICT_MODE": "true"}},
]
