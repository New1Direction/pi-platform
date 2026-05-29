"""Parity spec for PiSolidityPriceFeedFallbackSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityPriceFeedFallbackSentry"

_mod = load_py_agent("pi_solidity_price_feed_fallback_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityPriceFeedFallbackSentry()
    out = agent.audit_price_feed_fallback(_mod.PriceFeedFallbackInput(**data))
    return out.model_dump()


# A contract that reads an oracle but provides no fallback -> vulnerable.
_VULN = "\n".join(
    [
        "contract Feed {",
        "    function getQuote() public view returns (uint) {",
        "        (, int256 price, , ,) = oracle.latestRoundData();",
        "        return uint(price);",
        "    }",
        "}",
    ]
)

# Reads an oracle but has a TWAP fallback -> secure.
_FALLBACK_TWAP = "\n".join(
    [
        "contract Feed {",
        "    function getQuote() public view returns (uint) {",
        "        uint p = oracle.latestRoundData();",
        "        if (stale) p = getTwap();",
        "        return p;",
        "    }",
        "}",
    ]
)

# Uses getPrice with a try/catch (the word 'catch' counts as a fallback).
_FALLBACK_CATCH = "\n".join(
    [
        "contract Feed {",
        "    function quote() external {",
        "        try primary.getPrice() returns (uint p) {",
        "            last = p;",
        "        } catch {",
        "            last = backupOracle.getPrice();",
        "        }",
        "    }",
        "}",
    ]
)

# Multiple functions: one vulnerable, one safe (secondary feed), one no-oracle.
_MIXED = "\n".join(
    [
        "contract Multi {",
        "    function unsafe() public {",
        "        price = chainlink.latestRoundData();",
        "    }",
        "    function safe() public {",
        "        price = secondaryFeed.getPrice();",
        "    }",
        "    function plain(uint a) public {",
        "        total = a + 1;",
        "    }",
        "}",
    ]
)

# A header with no body brace: `[^{]*` swallows the next function (regex quirk).
_NO_BRACE = "\n".join(
    [
        "function noBody() external returns (uint)",
        "    function last() public { return getPrice(); }",
        "}",
    ]
)

# No functions at all.
_NO_FUNCS = "contract Empty { uint public x = 1; }"

SAMPLES = [
    # Clean / no oracle reads -> PASSED.
    {"input": {"file_path": "Feed.sol", "solidity_code": _NO_FUNCS}},
    # Vulnerable: oracle read, no fallback -> REJECTED (strict).
    {"input": {"file_path": "Feed.sol", "solidity_code": _VULN},
     "env": {"PI_ORACLE_FALLBACK_STRICT_MODE": "true"}},
    # TWAP fallback present -> secure.
    {"input": {"file_path": "Feed.sol", "solidity_code": _FALLBACK_TWAP}},
    # try/catch fallback present -> secure.
    {"input": {"file_path": "Feed.sol", "solidity_code": _FALLBACK_CATCH}},
    # Mixed: only the unsafe function is flagged.
    {"input": {"file_path": "Multi.sol", "solidity_code": _MIXED},
     "env": {"PI_ORACLE_FALLBACK_STRICT_MODE": "true"}},
    # Regex backtracking quirk: header without a brace.
    {"input": {"file_path": "Quirk.sol", "solidity_code": _NO_BRACE},
     "env": {"PI_ORACLE_FALLBACK_STRICT_MODE": "true"}},
    # Empty source -> PASSED.
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    # check_level override (does not affect logic) on a vulnerable input.
    {"input": {"file_path": "Feed.sol", "solidity_code": _VULN, "check_level": "LENIENT"},
     "env": {"PI_ORACLE_FALLBACK_STRICT_MODE": "true"}},
    # Non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "Feed.sol", "solidity_code": _VULN},
     "env": {"PI_ORACLE_FALLBACK_STRICT_MODE": "false"}},
]
