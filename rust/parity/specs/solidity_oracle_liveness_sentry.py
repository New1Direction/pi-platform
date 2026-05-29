"""Parity spec for PiSolidityOracleLivenessSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityOracleLivenessSentry"

_mod = load_py_agent("pi_solidity_oracle_liveness_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityOracleLivenessSentry()
    out = agent.audit_oracle_liveness(_mod.OracleLivenessInput(**data))
    return out.model_dump()


# A fully-validated oracle read: updatedAt unpacked, freshness checked,
# answer validated -> secure.
_SECURE = """
function getPrice() public view returns (uint256) {
    (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
    require(block.timestamp - updatedAt < 3600, "stale");
    require(answer > 0, "bad price");
    return uint256(answer);
}
"""

# Missing everything: reads latestRoundData with no validation at all.
_NO_VALIDATION = """
function getPrice() public view returns (int256) {
    (, int256 answer, , , ) = feed.latestRoundData();
    return answer;
}
"""

# Has updatedAt + freshness, but NO answer validation -> still flagged.
_NO_ANSWER_CHECK = """
function readFeed() external view returns (int256) {
    (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
    require(block.timestamp - updatedAt < 1 hours);
    return answer;
}
"""

# Has updatedAt + answer check, but NO freshness comparison -> flagged.
_NO_FRESHNESS = """
function spotPrice() public view returns (uint256) {
    (uint80 roundId, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
    require(answer > 0);
    return uint256(answer);
}
"""

# Uses the require(updatedAt != 0) freshness form + price > 0 answer form -> secure.
_SECURE_ALT = """
function latest() external view returns (uint256) {
    (, int256 price, , uint256 updatedAt, ) = oracle.latestRoundData();
    require(updatedAt != 0);
    require(price > 0);
    return uint256(price);
}
"""

# Multiple functions: one secure oracle read, one vulnerable, one with no oracle.
_MULTI = """
function safeRead() public view returns (uint256) {
    (, int256 answer, , uint256 updatedAt, ) = feed.latestRoundData();
    require(updatedAt > 0);
    require(answer > 0);
    return uint256(answer);
}

function unsafeRead() public view returns (int256) {
    (, int256 answer, , , ) = feed.latestRoundData();
    return answer;
}

function noOracle() public pure returns (uint256) {
    return 42;
}
"""

# No oracle usage at all -> secure (no functions flagged).
_NO_ORACLE = """
function add(uint256 a, uint256 b) public pure returns (uint256) {
    return a + b;
}
"""

SAMPLES = [
    {"input": {"file_path": "Vault.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _NO_VALIDATION}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _NO_ANSWER_CHECK}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _NO_FRESHNESS}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _SECURE_ALT}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _NO_ORACLE}},
    {"input": {"file_path": "Vault.sol", "solidity_code": ""}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _NO_VALIDATION, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Vault.sol", "solidity_code": _NO_VALIDATION},
     "env": {"PI_ORACLE_LIVENESS_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "Vault.sol", "solidity_code": _NO_VALIDATION},
     "env": {"PI_ORACLE_LIVENESS_STRICT_MODE": "true"}},
]
