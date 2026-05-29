"""Parity spec for PiUniswapV3PoolSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiUniswapV3PoolSentry"

_mod = load_py_agent("pi_uniswap_v3_pool_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiUniswapV3PoolSentry()
    out = agent.audit_uniswap_v3(_mod.UniV3SentryInput(**data))
    return out.model_dump()


# A function that uses slot0 WITHOUT a TWAP observe fallback -> vulnerable.
_SLOT0_VULN = "\n".join(
    [
        "contract PriceFeed {",
        "    function getPrice() public view returns (uint160) {",
        "        (uint160 sqrtPriceX96,,,,,,) = pool.slot0();",
        "        return sqrtPriceX96;",
        "    }",
        "}",
    ]
)

# A function that uses observe() (TWAP) -> safe even if it touches slot0.
_OBSERVE_SAFE = "\n".join(
    [
        "contract SafeFeed {",
        "    function twapPrice() public view returns (int56) {",
        "        (int56[] memory tickCumulatives,) = pool.observe(secondsAgos);",
        "        return tickCumulatives[0];",
        "    }",
        "}",
    ]
)

# Function that uses BOTH slot0 and observe in the same body -> safe (has fallback).
_BOTH_SAFE = "\n".join(
    [
        "contract HybridFeed {",
        "    function price() public view returns (uint) {",
        "        (uint160 spot,,,,,,) = pool.slot0();",
        "        (int56[] memory tc,) = pool.observe(secondsAgos);",
        "        return uint(spot) + uint(uint56(tc[0]));",
        "    }",
        "}",
    ]
)

# Multiple functions: one vulnerable (slot0 only), one safe (observe).
_MIXED = "\n".join(
    [
        "contract Mixed {",
        "    function badSpot() external view returns (uint160) {",
        "        (uint160 s,,,,,,) = pool.slot0();",
        "        return s;",
        "    }",
        "    function goodTwap() external view returns (int56) {",
        "        (int56[] memory t,) = pool.observe(ago);",
        "        return t[0];",
        "    }",
        "    function plain() external pure returns (uint) {",
        "        return 1;",
        "    }",
        "}",
    ]
)

# No functions matching at all -> secure / PASSED.
_NO_FUNCS = "contract Empty { uint public x = 5; }"

SAMPLES = [
    # Clean: a single TWAP-protected function.
    {"input": {"file_path": "Safe.sol", "solidity_code": _OBSERVE_SAFE}},
    # Vulnerable: slot0 without observe -> REJECTED_UNIV3_RISK under strict default.
    {"input": {"file_path": "Vuln.sol", "solidity_code": _SLOT0_VULN}},
    # slot0 + observe in same body -> safe.
    {"input": {"file_path": "Hybrid.sol", "solidity_code": _BOTH_SAFE}},
    # Mixed file with one vulnerable and one safe function.
    {"input": {"file_path": "Mixed.sol", "solidity_code": _MIXED}},
    # No matching functions.
    {"input": {"file_path": "Empty.sol", "solidity_code": _NO_FUNCS}},
    # Empty source.
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    # check_level override (does not affect logic, exercises the field).
    {"input": {"file_path": "Vuln.sol", "solidity_code": _SLOT0_VULN, "check_level": "MEDIUM"}},
    # env: non-strict -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "Vuln.sol", "solidity_code": _SLOT0_VULN},
     "env": {"PI_UNIV3_STRICT_MODE": "false"}},
    # env: strict explicitly -> REJECTED path.
    {"input": {"file_path": "Vuln.sol", "solidity_code": _SLOT0_VULN},
     "env": {"PI_UNIV3_STRICT_MODE": "true"}},
]
