"""Parity spec for PiSolidityExternalContractsReturnCheck.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityExternalContractsReturnCheck"

_mod = load_py_agent("pi_solidity_external_contracts_return_check.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityExternalContractsReturnCheck()
    out = agent.audit_external_returns(_mod.ExternalContractsReturnInput(**data))
    return out.model_dump()


# Clean / passing: assigned + checked low-level call.
_CHECKED = (
    "function exec(address t) public { (bool success, ) = t.call(data); require(success); }"
)
# Unchecked delegatecall -> flagged.
_UNCHECKED_DELEGATE = "function exec(address t) public { t.delegatecall(data); }"
# Unchecked staticcall -> flagged.
_UNCHECKED_STATIC = "function q(address t) view { t.staticcall(data); }"
# Assigned to success but no require/assert/if/revert anywhere -> flagged.
_ASSIGNED_NO_CHECK = "function exec(address t) public { (bool success, ) = t.call(data); }"
# Two functions: first unchecked (flagged once), second checked (clean).
_TWO_FUNCS = (
    "function a(address t){ t.call(x); } "
    "function b(address t){ (bool ok,)=t.call(y); require(ok); }"
)
# Multi-line contract, checked call -> clean.
_MULTILINE_CLEAN = "\n".join(
    [
        "contract C {",
        "    function pay(address to) public {",
        "        (bool ok, ) = to.call(payload);",
        "        if (!ok) { revert(); }",
        "    }",
        "}",
    ]
)
# No functions / no low-level calls -> clean.
_NO_FUNC = "uint256 x = 5;"

SAMPLES = [
    {"input": {"file_path": "a.sol", "solidity_code": _CHECKED}},
    {"input": {"file_path": "a.sol", "solidity_code": _UNCHECKED_DELEGATE}},
    {"input": {"file_path": "a.sol", "solidity_code": _UNCHECKED_STATIC}},
    {"input": {"file_path": "a.sol", "solidity_code": _ASSIGNED_NO_CHECK}},
    {"input": {"file_path": "a.sol", "solidity_code": _TWO_FUNCS}},
    {"input": {"file_path": "a.sol", "solidity_code": _MULTILINE_CLEAN}},
    {"input": {"file_path": "a.sol", "solidity_code": _NO_FUNC}},
    # empty / edge input
    {"input": {"file_path": "a.sol", "solidity_code": ""}},
    # check_level override does not affect logic, but exercises the field
    {"input": {"file_path": "a.sol", "solidity_code": _UNCHECKED_DELEGATE, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "a.sol", "solidity_code": _UNCHECKED_DELEGATE},
     "env": {"PI_EXTERNAL_CONTRACTS_RETURN_STRICT_MODE": "false"}},
    # strict env explicit -> REJECTED path
    {"input": {"file_path": "a.sol", "solidity_code": _UNCHECKED_DELEGATE},
     "env": {"PI_EXTERNAL_CONTRACTS_RETURN_STRICT_MODE": "true"}},
]
