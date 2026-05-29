"""Parity spec for PiReadOnlyOracleManipulationSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiReadOnlyOracleManipulationSentry"

_mod = load_py_agent("pi_read_only_oracle_manipulation_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiReadOnlyOracleManipulationSentry()
    out = agent.audit_read_only_oracle(_mod.ReadOnlyOracleInput(**data))
    return out.model_dump()


# A function that uses a secondary oracle (latestRoundData) -> has fallback -> safe.
_SECURE = (
    "function getPrice() public view returns (uint256) {\n"
    "    (, int256 answer, , ,) = priceFeed.latestRoundData();\n"
    "    uint256 bal = token.balanceOf(address(this));\n"
    "    return uint256(answer);\n"
    "}"
)

# Spot reserves + balanceOf, no fallback -> vulnerable.
_VULN_RESERVES = (
    "function getPrice() public view returns (uint256) {\n"
    "    (uint112 r0, uint112 r1, ) = pair.getReserves();\n"
    "    uint256 bal = token.balanceOf(address(this));\n"
    "    return (uint256(r0) * 1e18) / uint256(r1);\n"
    "}"
)

# queryBatchSwap + function name contains 'price' -> vulnerable.
_VULN_BATCHSWAP = (
    "function spotPriceFromVault() external returns (int256) {\n"
    "    int256[] memory deltas = vault.queryBatchSwap(kind, swaps, assets, funds);\n"
    "    return deltas[0];\n"
    "}"
)

# get_dy + function name contains 'oracle' -> vulnerable.
_VULN_GETDY = (
    "function oracleQuote() public view returns (uint256) {\n"
    "    uint256 dy = curvePool.get_dy(0, 1, 1e18);\n"
    "    return dy;\n"
    "}"
)

# get_dy + name has 'oracle' but body has a 'twap' fallback (case-insensitive) -> safe.
_FALLBACK_TWAP = (
    "function oracleQuote() public view returns (uint256) {\n"
    "    uint256 dy = curvePool.get_dy(0, 1, 1e18);\n"
    "    uint256 twapPrice = computeTWAP();\n"
    "    return twapPrice;\n"
    "}"
)

# Uses getReserves + balanceOf but calls observe() -> has fallback -> safe.
_FALLBACK_OBSERVE = (
    "function getPrice() public view returns (uint256) {\n"
    "    (uint112 r0, , ) = pair.getReserves();\n"
    "    uint256 bal = token.balanceOf(msg.sender);\n"
    "    pool.observe(secondsAgos);\n"
    "    return r0;\n"
    "}"
)

# Spot pricing pattern present but trigger keywords absent (no getReserves/etc) -> safe.
_NO_SPOT = (
    "function transfer(address to, uint256 amount) public returns (bool) {\n"
    "    balances[msg.sender] -= amount;\n"
    "    balances[to] += amount;\n"
    "    return true;\n"
    "}"
)

# Multiple functions: one safe, one vulnerable.
_MULTI = (
    "function safeOne() public view returns (uint) {\n"
    "    return priceFeed.latestRoundData();\n"
    "}\n"
    "function getPrice() public view returns (uint) {\n"
    "    uint r = pair.getReserves();\n"
    "    uint b = token.balanceOf(address(this));\n"
    "    return r + b;\n"
    "}"
)

SAMPLES = [
    # clean/passing
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE}},
    # vulnerable: getReserves + balanceOf
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_RESERVES}},
    # vulnerable: queryBatchSwap + name contains 'price'
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_BATCHSWAP}},
    # vulnerable: get_dy + name contains 'oracle'
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_GETDY}},
    # safe via twap fallback
    {"input": {"file_path": "C.sol", "solidity_code": _FALLBACK_TWAP}},
    # safe via observe() fallback
    {"input": {"file_path": "C.sol", "solidity_code": _FALLBACK_OBSERVE}},
    # safe: no spot pricing trigger keywords
    {"input": {"file_path": "C.sol", "solidity_code": _NO_SPOT}},
    # multiple functions, mixed
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI}},
    # empty / edge input
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    # check_level override (does not affect logic, but exercises the field)
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_GETDY, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_RESERVES},
     "env": {"PI_READ_ONLY_ORACLE_STRICT_MODE": "false"}},
    # strict env -> REJECTED path
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_RESERVES},
     "env": {"PI_READ_ONLY_ORACLE_STRICT_MODE": "true"}},
]
