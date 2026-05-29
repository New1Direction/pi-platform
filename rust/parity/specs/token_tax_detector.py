"""Parity spec for PiTokenTaxDetector.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiTokenTaxDetector"

_mod = load_py_agent("pi_token_tax_detector.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiTokenTaxDetector()
    out = agent.audit_token_tax(_mod.TokenTaxInput(**data))
    return out.model_dump()


# A fully compliant transfer: returns bool, emits Transfer, no fee/tax math,
# no exclusion checks -> PASSED, secure.
_CLEAN = "\n".join(
    [
        "contract Token {",
        "    function transfer(address to, uint256 amount) public returns (bool) {",
        "        balances[msg.sender] += amount;",
        "        balances[to] += amount;",
        "        emit Transfer(msg.sender, to, amount);",
        "        return true;",
        "    }",
        "}",
    ]
)

# Fee-on-transfer: tax pattern (fee) + arithmetic operator -> vulnerable.
_FEE = "\n".join(
    [
        "function transfer(address to, uint256 amount) public returns (bool) {",
        "    uint256 fee = amount / 100;",
        "    uint256 net = amount - fee;",
        "    balances[to] += net;",
        "    emit Transfer(msg.sender, to, net);",
        "    return true;",
        "}",
    ]
)

# Blacklist exclusion backdoor path (no fee math, but exclusion keyword).
_BLACKLIST = "\n".join(
    [
        "function transferFrom(address f, address t, uint256 amt) public returns (bool) {",
        "    require(!blacklist[f], 'blocked');",
        "    emit Transfer(f, t, amt);",
        "    return true;",
        "}",
    ]
)

# Compliance-only warnings: no bool return, and missing Transfer event.
# 'returns' present but 'bool' absent triggers the non-boolean warning;
# absence of 'emit Transfer(' triggers the event warning. No vulnerability,
# so is_secure stays True and status is PASSED.
_NOBOOL_NOEVENT = "\n".join(
    [
        "function transfer(address to, uint256 amount) public returns (uint256) {",
        "    balances[to] = amount;",
        "    return amount;",
        "}",
    ]
)

# A transfer with tax keyword in a comment that gets stripped, plus a block
# comment with arithmetic; exercises comment cleaning. The // line comment
# hides 'fee', and the /* */ block comment hides '-'. After cleaning there is
# no fee/tax + arithmetic combination, so it should NOT be flagged as a tax.
_COMMENTS = "\n".join(
    [
        "function transfer(address to, uint256 amount) public returns (bool) {",
        "    // fee logic was removed: amount - fee",
        "    /* old: tax = amount * rate / 100 */",
        "    balances[to] += amount;",
        "    emit Transfer(msg.sender, to, amount);",
        "    return true;",
        "}",
    ]
)

# Non-transfer functions are ignored entirely (constructor, custom name).
_NON_TRANSFER = "\n".join(
    [
        "constructor() {",
        "    owner = msg.sender;",
        "}",
        "function setFee(uint256 fee) public {",
        "    feeRate = fee / 2;",
        "}",
    ]
)

# Interface declaration (function ... ;) with no body should be skipped by the
# extractor (semicolon before any brace), so nothing is flagged.
_INTERFACE_DECL = "\n".join(
    [
        "interface IERC20 {",
        "    function transfer(address to, uint256 amount) external returns (bool);",
        "}",
    ]
)

# Multiple vulnerable functions: both fee math AND exclusion in the same func,
# plus a second tax function -> dedup of vulnerable_functions matters.
_MULTI = "\n".join(
    [
        "function transfer(address to, uint256 amount) public returns (bool) {",
        "    uint256 burn = amount * 2 / 100;",
        "    if (excludeFromFee[to]) { amount = amount; }",
        "    emit Transfer(msg.sender, to, amount);",
        "    return true;",
        "}",
        "function transferFrom(address f, address t, uint256 amount) public {",
        "    uint256 tax = amount - rate;",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Token.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "Fee.sol", "solidity_code": _FEE}},
    {"input": {"file_path": "Black.sol", "solidity_code": _BLACKLIST}},
    {"input": {"file_path": "Compliance.sol", "solidity_code": _NOBOOL_NOEVENT}},
    {"input": {"file_path": "Comments.sol", "solidity_code": _COMMENTS}},
    {"input": {"file_path": "NonTransfer.sol", "solidity_code": _NON_TRANSFER}},
    {"input": {"file_path": "Iface.sol", "solidity_code": _INTERFACE_DECL}},
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Lenient.sol", "solidity_code": _FEE, "check_level": "MEDIUM"}},
    # Non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "Fee.sol", "solidity_code": _FEE},
     "env": {"PI_TOKENTAX_STRICT_MODE": "false"}},
    # Strict env -> REJECTED path.
    {"input": {"file_path": "Fee.sol", "solidity_code": _FEE},
     "env": {"PI_TOKENTAX_STRICT_MODE": "true"}},
]
