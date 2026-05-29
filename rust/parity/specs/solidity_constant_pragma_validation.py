"""Parity spec for PiSolidityConstantPragmaValidation.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityConstantPragmaValidation"

_mod = load_py_agent("pi_solidity_constant_pragma_validation.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityConstantPragmaValidation()
    out = agent.audit_constant_pragma(_mod.ConstantPragmaInput(**data))
    return out.model_dump()


_LOCKED = "pragma solidity 0.8.20;\n\ncontract Vault {}"
_CARET = "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract Token {}"
_GTE = "pragma solidity >=0.8.0;\n\ncontract A {}"
_RANGE = "pragma solidity >=0.7.0 <0.9.0;\n\ncontract B {}"
_LTE = "pragma solidity <=0.8.20;\n"
_NO_PRAGMA = "// just a comment\ncontract NoPragma {}"
_MULTI_PRAGMA = "\n".join(
    [
        "pragma solidity ^0.8.0;",
        "pragma abicoder v2;",
        "contract Multi {}",
    ]
)

SAMPLES = [
    # clean / locked version -> PASSED
    {"input": {"file_path": "Vault.sol", "solidity_code": _LOCKED}},
    # floating caret -> REJECTED (strict default)
    {"input": {"file_path": "Token.sol", "solidity_code": _CARET}},
    # floating >= -> REJECTED
    {"input": {"file_path": "A.sol", "solidity_code": _GTE}},
    # floating range (>= and <) -> REJECTED
    {"input": {"file_path": "B.sol", "solidity_code": _RANGE}},
    # floating <= -> REJECTED
    {"input": {"file_path": "C.sol", "solidity_code": _LTE}},
    # no pragma at all -> PASSED (no findings)
    {"input": {"file_path": "NoPragma.sol", "solidity_code": _NO_PRAGMA}},
    # first pragma is the solidity one and is floating -> REJECTED
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI_PRAGMA}},
    # empty input -> PASSED
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    # check_level provided explicitly (does not affect logic) -> PASSED
    {"input": {"file_path": "Vault.sol", "solidity_code": _LOCKED, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Token.sol", "solidity_code": _CARET},
     "env": {"PI_CONSTANT_PRAGMA_STRICT_MODE": "false"}},
    # strict env explicit -> REJECTED path
    {"input": {"file_path": "Token.sol", "solidity_code": _CARET},
     "env": {"PI_CONSTANT_PRAGMA_STRICT_MODE": "true"}},
]
