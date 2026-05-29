"""Parity spec for PiSolidityUndeclaredReturnVariableSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityUndeclaredReturnVariableSentry"

_mod = load_py_agent("pi_solidity_undeclared_return_variable_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityUndeclaredReturnVariableSentry()
    out = agent.audit_undeclared_returns(_mod.UndeclaredReturnVariableInput(**data))
    return out.model_dump()


# Clean: named return that is assigned.
_ASSIGNED = "function getVal() public view returns (uint256 value) { value = 42; }"
# Clean: named return that is explicitly returned.
_RETURNED = "function getVal() public view returns (uint256 value) { return value; }"
# Vulnerable: named return never assigned nor returned.
_UNASSIGNED = "function getVal() public view returns (uint256 value) { uint256 x = 1; }"
# Unnamed return (only a type) -> never flagged.
_UNNAMED = "function getVal() public view returns (uint256) { uint256 x = 1; }"
# Compound-assignment counts as assigned (matched by [-+=/]?=).
_COMPOUND = "function acc() public returns (uint256 total) { total += 5; }"
# Multiple named returns, second one is undeclared -> flagged once.
_MULTI_RETURN = (
    "function pair() public returns (uint256 a, address admin) { a = 1; }"
)
# Two functions: one safe, one vulnerable.
_TWO_FUNCS = "\n".join(
    [
        "function safe() public returns (uint256 ok) { ok = 1; }",
        "function leaky() public returns (address owner) { uint256 y = 0; }",
    ]
)
# Keyword-only slot (e.g. 'uint256 memory') -> var_name is a keyword, skipped.
_KEYWORD = "function buf() public returns (bytes memory) { uint256 x = 1; }"

SAMPLES = [
    {"input": {"file_path": "C.sol", "solidity_code": _ASSIGNED}},
    {"input": {"file_path": "C.sol", "solidity_code": _RETURNED}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNASSIGNED}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNNAMED}},
    {"input": {"file_path": "C.sol", "solidity_code": _COMPOUND}},
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI_RETURN}},
    {"input": {"file_path": "C.sol", "solidity_code": _TWO_FUNCS}},
    {"input": {"file_path": "C.sol", "solidity_code": _KEYWORD}},
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    # check_level passthrough (does not affect logic).
    {"input": {"file_path": "C.sol", "solidity_code": _UNASSIGNED, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "C.sol", "solidity_code": _UNASSIGNED},
     "env": {"PI_UNDECLARED_RETURN_VARIABLE_STRICT_MODE": "false"}},
    # strict env explicitly -> REJECTED path.
    {"input": {"file_path": "C.sol", "solidity_code": _UNASSIGNED},
     "env": {"PI_UNDECLARED_RETURN_VARIABLE_STRICT_MODE": "true"}},
]
