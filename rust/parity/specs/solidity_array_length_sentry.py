"""Parity spec for PiSolidityArrayLengthSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityArrayLengthSentry"

_mod = load_py_agent("pi_solidity_array_length_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityArrayLengthSentry()
    out = agent.audit_array_length(_mod.ArrayLengthInput(**data))
    return out.model_dump()


# Clean: array param + length loop, but with a require(...) limit check -> secure.
_SECURE = "\n".join(
    [
        "pragma solidity ^0.8.0;",
        "contract Vault {",
        "    function batch(uint256[] calldata data) external {",
        "        require(data.length <= MAX_LEN, \"too big\");",
        "        for (uint i = 0; i < data.length; i++) { sum += data[i]; }",
        "    }",
        "}",
    ]
)

# Vulnerable: array param iterated over .length with NO limit check.
_VULN = "\n".join(
    [
        "contract Airdrop {",
        "    function distribute(address[] memory users) public {",
        "        for (uint i = 0; i < users.length; i++) { pay(users[i]); }",
        "    }",
        "}",
    ]
)

# Two functions: one safe (has require), one vulnerable -> flags only the second.
_MIXED = "\n".join(
    [
        "contract Mixed {",
        "    function safe(uint256[] calldata a) external {",
        "        require(a.length < 100);",
        "        for (uint i = 0; i < a.length; i++) {}",
        "    }",
        "    function unsafe(bytes32[] memory hashes) public {",
        "        for (uint i = 0; i < hashes.length; i++) {}",
        "    }",
        "}",
    ]
)

# Array param present but NOT iterated over its .length -> secure (no finding).
_NO_LENGTH_USE = "\n".join(
    [
        "contract Store {",
        "    function save(uint256[] calldata vals) external {",
        "        firstVal = vals[0];",
        "    }",
        "}",
    ]
)

# Private function with vulnerable pattern -> NOT matched (no external/public).
_PRIVATE = "function helper(uint[] memory a) private { for(uint i;i<a.length;i++){} }"

# Function with no array parameter at all -> secure.
_NO_ARRAY = "\n".join(
    [
        "contract Counter {",
        "    function inc(uint256 amount) external { count += amount; }",
        "}",
    ]
)

# calldata array, loops over length, no require -> vulnerable.
_CALLDATA_VULN = "\n".join(
    [
        "contract Loop {",
        "    function run(uint256[] calldata items) external {",
        "        uint total;",
        "        for (uint i = 0; i < items.length; i++) { total += items[i]; }",
        "    }",
        "}",
    ]
)

SAMPLES = [
    # clean / passing
    {"input": {"file_path": "Vault.sol", "solidity_code": _SECURE}},
    # vulnerable (strict default via env)
    {"input": {"file_path": "Airdrop.sol", "solidity_code": _VULN},
     "env": {"PI_ARRAY_LENGTH_STRICT_MODE": "true"}},
    # mixed: only the unsafe function flagged
    {"input": {"file_path": "Mixed.sol", "solidity_code": _MIXED},
     "env": {"PI_ARRAY_LENGTH_STRICT_MODE": "true"}},
    # array param but no .length iteration -> secure
    {"input": {"file_path": "Store.sol", "solidity_code": _NO_LENGTH_USE}},
    # private function -> not matched -> secure
    {"input": {"file_path": "Helper.sol", "solidity_code": _PRIVATE}},
    # no array param -> secure
    {"input": {"file_path": "Counter.sol", "solidity_code": _NO_ARRAY}},
    # empty input -> secure, no functions
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    # custom check_level still parses; vulnerable strict path
    {"input": {"file_path": "Loop.sol", "solidity_code": _CALLDATA_VULN, "check_level": "LENIENT"},
     "env": {"PI_ARRAY_LENGTH_STRICT_MODE": "true"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Airdrop.sol", "solidity_code": _VULN},
     "env": {"PI_ARRAY_LENGTH_STRICT_MODE": "false"}},
]
