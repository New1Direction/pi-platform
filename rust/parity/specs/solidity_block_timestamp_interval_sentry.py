"""Parity spec for PiSolidityBlockTimestampIntervalSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityBlockTimestampIntervalSentry"

_mod = load_py_agent("pi_solidity_block_timestamp_interval_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityBlockTimestampIntervalSentry()
    out = agent.audit_timestamp_interval(_mod.TimestampIntervalInput(**data))
    return out.model_dump()


# Clean/passing: claim function with a proper interval check.
_SECURE_GE = "\n".join(
    [
        "function claim() external {",
        "    require(block.timestamp >= lastClaim + INTERVAL);",
        "    _payout(msg.sender);",
        "}",
    ]
)

# Passing via the `+ <= block.timestamp` form.
_SECURE_LE = "\n".join(
    [
        "function stakeWithdraw() public {",
        "    require(lastStake + lockPeriod <= block.timestamp);",
        "    _release();",
        "}",
    ]
)

# Passing via the `block.timestamp - x >= y` subtraction form.
_SECURE_SUB = "\n".join(
    [
        "function distribute() external {",
        "    require(block.timestamp - lastDistribution >= MIN_GAP);",
        "    _spread();",
        "}",
    ]
)

# Vulnerable: keyword function (claim) referencing block.timestamp w/o interval check.
_VULN_CLAIM = "\n".join(
    [
        "function claimReward() external {",
        "    uint256 nowTs = block.timestamp;",
        "    _payout(nowTs);",
        "}",
    ]
)

# Vulnerable: vesting function with timestamp but only an unrelated comparison.
_VULN_VEST = "\n".join(
    [
        "function vest(address to) public {",
        "    if (block.timestamp > 0) {",
        "        _grant(to);",
        "    }",
        "}",
    ]
)

# Multi-function: one secure (withdraw w/ check) + one vulnerable (distribute) +
# one non-keyword function that uses block.timestamp but must NOT be flagged.
_MULTI = "\n".join(
    [
        "function getTime() public view returns (uint256) {",
        "    return block.timestamp;",
        "}",
        "function withdraw() external {",
        "    require(block.timestamp >= lastWithdraw + COOLDOWN);",
        "    _send();",
        "}",
        "function distributeRewards() external {",
        "    uint256 amt = totalPool / users;",
        "    _credit(block.timestamp);",
        "}",
    ]
)

# Function with no block.timestamp at all -> ignored entirely.
_NO_TIMESTAMP = "\n".join(
    [
        "function claim() external {",
        "    _payout(msg.sender);",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE_GE}},
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE_LE}},
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE_SUB}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_CLAIM}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_VEST}},
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "C.sol", "solidity_code": _NO_TIMESTAMP}},
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_CLAIM, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_CLAIM},
     "env": {"PI_TIMESTAMP_INTERVAL_STRICT_MODE": "false"}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_CLAIM},
     "env": {"PI_TIMESTAMP_INTERVAL_STRICT_MODE": "true"}},
]
