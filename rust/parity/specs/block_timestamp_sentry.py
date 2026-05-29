"""Parity spec for PiBlockTimestampSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiBlockTimestampSentry"

_mod = load_py_agent("pi_block_timestamp_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiBlockTimestampSentry()
    out = agent.audit_timestamp(_mod.BlockTimestampInput(**data))
    return out.model_dump()


# --- Sample Solidity bodies -------------------------------------------------

# Clean contract: no block.timestamp / now reliance at all.
_CLEAN = "contract C { function transfer(address to, uint amt) public { balances[to] += amt; } }"

# Mode 1: timestamp used for pseudo-randomness via keccak256 + modulo.
_RANDOM = (
    "contract Lottery {\n"
    "    function pickWinner() public {\n"
    "        uint winner = uint(keccak256(abi.encodePacked(block.timestamp, block.difficulty))) % players.length;\n"
    "        payable(players[winner]).transfer(address(this).balance);\n"
    "    }\n"
    "}"
)

# Mode 1 variant: timestamp + a 'random'-named usage (case-insensitive).
_RANDOM_WORD = (
    "contract Game {\n"
    "    function roll() external {\n"
    "        uint randomValue = uint(block.timestamp);\n"
    "    }\n"
    "}"
)

# Mode 2: inequality comparison on block.timestamp WITHOUT a standard margin
# -> expiration warning (finding only, not vulnerable).
_EXPIRE_NO_MARGIN = (
    "contract Vault {\n"
    "    function withdraw() public {\n"
    "        require(block.timestamp > unlockTime);\n"
    "        msg.sender.transfer(amount);\n"
    "    }\n"
    "}"
)

# Mode 2 safe: inequality comparison WITH a standard margin ('days') -> no finding.
_EXPIRE_WITH_MARGIN = (
    "contract Timelock {\n"
    "    function release() public {\n"
    "        require(block.timestamp > start + 7 days);\n"
    "    }\n"
    "}"
)

# Uses 'now' (legacy alias) inside a comparison without margin -> expiration warning.
_NOW_COMPARE = (
    "contract Legacy {\n"
    "    function claim() public {\n"
    "        if (now < endTime) revert();\n"
    "    }\n"
    "}"
)

# Comments must be stripped before scanning: the only block.timestamp+% is inside
# comments, so this should be clean (no findings, no vulnerable funcs).
_COMMENTED = (
    "contract Documented {\n"
    "    function safe() public {\n"
    "        // uint r = block.timestamp % 7;\n"
    "        /* keccak256(block.timestamp) random demo */\n"
    "        uint x = 42;\n"
    "    }\n"
    "}"
)

# Multiple functions: one random-vulnerable, one expiration-warning, one clean.
_MULTI = (
    "contract Mixed {\n"
    "    constructor() { owner = msg.sender; }\n"
    "    function entropy() public { uint e = block.timestamp % 256; }\n"
    "    function deadline() public { require(block.timestamp < expiry); }\n"
    "    function pure_fn() public pure returns (uint) { return 1; }\n"
    "}"
)

SAMPLES = [
    # clean contract -> PASSED (strict-mode irrelevant)
    {"input": {"file_path": "C.sol", "solidity_code": _CLEAN}},
    # randomness path, strict -> REJECTED
    {"input": {"file_path": "Lottery.sol", "solidity_code": _RANDOM},
     "env": {"PI_TIMESTAMP_STRICT_MODE": "true"}},
    # randomness path, lenient -> WARN, is_secure coerced back to True
    {"input": {"file_path": "Lottery.sol", "solidity_code": _RANDOM},
     "env": {"PI_TIMESTAMP_STRICT_MODE": "false"}},
    # 'random'-named usage + block.timestamp, strict -> REJECTED
    {"input": {"file_path": "Game.sol", "solidity_code": _RANDOM_WORD},
     "env": {"PI_TIMESTAMP_STRICT_MODE": "true"}},
    # expiration warning, no margin (finding only, still PASSED)
    {"input": {"file_path": "Vault.sol", "solidity_code": _EXPIRE_NO_MARGIN}},
    # expiration WITH margin -> no finding
    {"input": {"file_path": "Timelock.sol", "solidity_code": _EXPIRE_WITH_MARGIN}},
    # 'now' comparison without margin -> expiration warning
    {"input": {"file_path": "Legacy.sol", "solidity_code": _NOW_COMPARE}},
    # comments stripped -> clean
    {"input": {"file_path": "Documented.sol", "solidity_code": _COMMENTED}},
    # multiple functions, strict -> REJECTED, with both finding kinds
    {"input": {"file_path": "Mixed.sol", "solidity_code": _MULTI},
     "env": {"PI_TIMESTAMP_STRICT_MODE": "true"}},
    # multiple functions, lenient -> WARN
    {"input": {"file_path": "Mixed.sol", "solidity_code": _MULTI},
     "env": {"PI_TIMESTAMP_STRICT_MODE": "false"}},
    # empty / edge input -> no functions, PASSED
    {"input": {"file_path": "empty.sol", "solidity_code": ""}},
    # non-default check_level still honored by the model (no behavioural effect)
    {"input": {"file_path": "Lottery.sol", "solidity_code": _RANDOM, "check_level": "MEDIUM"},
     "env": {"PI_TIMESTAMP_STRICT_MODE": "true"}},
]
