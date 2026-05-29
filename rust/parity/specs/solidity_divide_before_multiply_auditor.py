"""Parity spec for PiSolidityDivideBeforeMultiplyAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityDivideBeforeMultiplyAuditor"

_mod = load_py_agent("pi_solidity_divide_before_multiply_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityDivideBeforeMultiplyAuditor()
    out = agent.audit_divide_multiply(_mod.DivideBeforeMultiplyInput(**data))
    return out.model_dump()


# Clean / passing: multiply happens before divide (safe ordering).
_SECURE = "function safe(uint a, uint b) public returns (uint) { return a * b / SCALE; }"

# Vulnerable path 1: operator `/` then `*`  (a / b * c).
_OP_ISSUE = "function bad(uint amount) public { uint r = amount / total * reward; }"

# Vulnerable path 2: SafeMath `.div(...).mul(...)`.
_SAFEMATH = "function calc(uint a) public { uint r = a.div(denominator).mul(factor); }"

# Multi-function source: one clean, one operator-issue, one safemath-issue.
_MULTI = "\n".join(
    [
        "contract Vault {",
        "    function ok(uint a, uint b) public { uint x = a * b / SCALE; }",
        "    function leaky(uint a) public {",
        "        uint share = a / supply * bonus;",
        "    }",
        "    function safemathy(uint a) public {",
        "        uint y = a.div(pool).mul(weight);",
        "    }",
        "}",
    ]
)

# No functions at all -> nothing to scan.
_NO_FUNCS = "uint256 public constant SCALE = 1e18;"

SAMPLES = [
    {"input": {"file_path": "Safe.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "Bad.sol", "solidity_code": _OP_ISSUE}},
    {"input": {"file_path": "Math.sol", "solidity_code": _SAFEMATH}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Const.sol", "solidity_code": _NO_FUNCS}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Bad.sol", "solidity_code": _OP_ISSUE, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Bad.sol", "solidity_code": _OP_ISSUE},
     "env": {"PI_DIVIDE_BEFORE_MULTIPLY_STRICT_MODE": "false"}},
    {"input": {"file_path": "Bad.sol", "solidity_code": _OP_ISSUE},
     "env": {"PI_DIVIDE_BEFORE_MULTIPLY_STRICT_MODE": "true"}},
]
