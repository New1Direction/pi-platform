"""Parity spec for PiSolidityCompilerBugsSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityCompilerBugsSentry"

_mod = load_py_agent("pi_solidity_compiler_bugs_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityCompilerBugsSentry()
    out = agent.audit_compiler_bugs(_mod.CompilerBugsInput(**data))
    return out.model_dump()


# Clean / passing pragma (no buggy release).
_CLEAN = "pragma solidity 0.8.20;\ncontract C {}"
# Yul Optimizer severe memory bug releases: 0.8.13 / 0.8.14 / 0.8.15.
_YUL_13 = "pragma solidity 0.8.13;"
_YUL_15 = "pragma solidity ^0.8.15;"
# ABI encoder v2 dynamic-array bug: 0.8.3 - 0.8.7.
_ABI_4 = "pragma solidity 0.8.4;"
# Caret/whitespace variant still resolves the locked version inside the pragma.
_ABI_7_WS = "pragma   solidity   >=0.8.7   ;"
# A version outside both buggy ranges.
_SAFE_OLD = "pragma solidity 0.7.6;"
# No pragma at all -> nothing to flag.
_NO_PRAGMA = "contract C { function f() public {} }"
# Multiple pragmas in one file: one buggy, one clean.
_MULTI = "\n".join(
    [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity 0.8.14;",
        "pragma solidity 0.8.20;",
        "contract A {}",
    ]
)

SAMPLES = [
    # Clean pragma, env unset -> default strict -> PASSED.
    {"input": {"file_path": "C.sol", "solidity_code": _CLEAN}},
    # Yul bug 0.8.13, strict env -> REJECTED.
    {"input": {"file_path": "C.sol", "solidity_code": _YUL_13},
     "env": {"PI_COMPILER_BUGS_STRICT_MODE": "true"}},
    # Yul bug 0.8.15 with caret, strict env -> REJECTED.
    {"input": {"file_path": "C.sol", "solidity_code": _YUL_15},
     "env": {"PI_COMPILER_BUGS_STRICT_MODE": "true"}},
    # ABI encoder bug 0.8.4, strict env -> REJECTED.
    {"input": {"file_path": "C.sol", "solidity_code": _ABI_4},
     "env": {"PI_COMPILER_BUGS_STRICT_MODE": "true"}},
    # ABI encoder bug 0.8.7 with whitespace, non-strict env -> WARN, is_secure coerced True.
    {"input": {"file_path": "C.sol", "solidity_code": _ABI_7_WS},
     "env": {"PI_COMPILER_BUGS_STRICT_MODE": "false"}},
    # Safe old version -> PASSED.
    {"input": {"file_path": "C.sol", "solidity_code": _SAFE_OLD}},
    # No pragma -> PASSED.
    {"input": {"file_path": "C.sol", "solidity_code": _NO_PRAGMA}},
    # Empty source -> PASSED.
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    # Multiple pragmas (one buggy 0.8.14), strict env -> REJECTED, single finding.
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI, "check_level": "MEDIUM"},
     "env": {"PI_COMPILER_BUGS_STRICT_MODE": "true"}},
    # Same buggy file but non-strict env -> WARN path.
    {"input": {"file_path": "C.sol", "solidity_code": _YUL_13},
     "env": {"PI_COMPILER_BUGS_STRICT_MODE": "false"}},
]
