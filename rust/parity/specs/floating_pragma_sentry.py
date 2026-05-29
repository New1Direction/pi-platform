"""Parity spec for PiFloatingPragmaSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiFloatingPragmaSentry"

_mod = load_py_agent("pi_floating_pragma_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiFloatingPragmaSentry()
    out = agent.audit_pragma(_mod.PragmaSentryInput(**data))
    return out.model_dump()


# A safe, locked, modern compiler version -> PASSED, no findings.
_LOCKED_OK = "pragma solidity 0.8.19;"
# Caret floating pragma -> floating finding + 0.8.0 buggy-version finding.
_FLOATING_CARET = "pragma solidity ^0.8.0;"
# Range / unbounded floating pragma.
_FLOATING_RANGE = "pragma solidity >=0.7.0 <0.9.0;"
# Locked but outdated (<0.8.0) -> outdated finding, but still secure.
_OUTDATED = "pragma solidity 0.7.6;"
# Locked but known-buggy 0.8.1 -> buggy-version finding, still secure.
_BUGGY_LOCKED = "pragma solidity 0.8.1;"
# No pragma directive at all -> file_header vulnerable.
_NO_PRAGMA = "contract C {\n    uint256 x;\n}"
# Multiple pragmas in one file (mixed safe + floating).
_MULTI = "\n".join(
    [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity 0.8.19;",
        "pragma solidity ^0.6.0;",
        "contract C {}",
    ]
)

SAMPLES = [
    # 1. clean / passing locked version
    {"input": {"file_path": "C.sol", "solidity_code": _LOCKED_OK}},
    # 2. floating caret pragma (strict default -> REJECTED)
    {"input": {"file_path": "C.sol", "solidity_code": _FLOATING_CARET}},
    # 3. floating range / unbounded pragma
    {"input": {"file_path": "C.sol", "solidity_code": _FLOATING_RANGE}},
    # 4. locked but outdated (<0.8.0)
    {"input": {"file_path": "C.sol", "solidity_code": _OUTDATED}},
    # 5. locked but known-buggy 0.8.1
    {"input": {"file_path": "C.sol", "solidity_code": _BUGGY_LOCKED}},
    # 6. no pragma at all
    {"input": {"file_path": "C.sol", "solidity_code": _NO_PRAGMA}},
    # 7. multiple pragmas (safe + floating outdated)
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI}},
    # 8. empty input (edge) -> treated as missing pragma
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    # 9. non-default check_level passes through harmlessly
    {"input": {"file_path": "C.sol", "solidity_code": _LOCKED_OK, "check_level": "MEDIUM"}},
    # 10. non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _FLOATING_CARET},
     "env": {"PI_PRAGMA_STRICT_MODE": "false"}},
    # 11. explicit strict env -> REJECTED path
    {"input": {"file_path": "C.sol", "solidity_code": _NO_PRAGMA},
     "env": {"PI_PRAGMA_STRICT_MODE": "true"}},
]
