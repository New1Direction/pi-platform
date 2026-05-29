"""Parity spec for PiSolidityDelegateCallToSelfSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityDelegateCallToSelfSentry"

_mod = load_py_agent("pi_solidity_delegate_call_to_self_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityDelegateCallToSelfSentry()
    out = agent.audit_delegatecall_self(_mod.DelegateCallSelfInput(**data))
    return out.model_dump()


# Clean: a delegatecall to an external target (not self).
_CLEAN = "\n".join(
    [
        "contract Vault {",
        "    function execute(address t, bytes memory d) public {",
        "        t.delegatecall(d);",
        "    }",
        "}",
    ]
)

# High-level Solidity self-delegatecall via address(this).
_SOLIDITY_ADDR_THIS = "\n".join(
    [
        "function attack(bytes memory d) public {",
        '    address(this).delegatecall(d);',
        "}",
    ]
)

# High-level Solidity self-delegatecall via bare `this`.
_SOLIDITY_THIS = "\n".join(
    [
        "function bounce() external {",
        "    this.delegatecall(payload);",
        "}",
    ]
)

# Inline assembly self-delegatecall targeting address(this).
_ASSEMBLY_SELF = "\n".join(
    [
        "function lowlevel() public {",
        "    assembly {",
        "        let r := delegatecall(gas(), address(this), 0, 0, 0, 0)",
        "    }",
        "}",
    ]
)

# Multiple functions: one clean, one vulnerable -- exercises func_blocks loop
# and the `\n\s*function` body boundary.
_MULTI = "\n".join(
    [
        "function safe(address t) public {",
        "    t.delegatecall(d);",
        "}",
        "",
        "function unsafe() public {",
        "    address( this ).delegatecall(d);",
        "}",
    ]
)

# `thisVar` must NOT match the `this` self-delegatecall pattern (no word match,
# but the inner regex `this\s*\.` naturally rejects because "Var" follows).
_FALSE_POSITIVE_THISVAR = "\n".join(
    [
        "function f() public {",
        "    thisVar.delegatecall(d);",
        "}",
    ]
)

# Multi-line argument list -> Python regex `(.*?)` cannot cross newlines, so the
# function header never matches and the body is never scanned (no findings).
_MULTILINE_ARGS = "\n".join(
    [
        "function f(",
        "    bytes memory d",
        ") public {",
        "    address(this).delegatecall(d);",
        "}",
    ]
)


SAMPLES = [
    {"input": {"file_path": "Vault.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "A.sol", "solidity_code": _SOLIDITY_ADDR_THIS}},
    {"input": {"file_path": "B.sol", "solidity_code": _SOLIDITY_THIS}},
    {"input": {"file_path": "C.sol", "solidity_code": _ASSEMBLY_SELF}},
    {"input": {"file_path": "D.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "E.sol", "solidity_code": _FALSE_POSITIVE_THISVAR}},
    {"input": {"file_path": "F.sol", "solidity_code": _MULTILINE_ARGS}},
    {"input": {"file_path": "empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "lvl.sol", "solidity_code": _SOLIDITY_ADDR_THIS, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "A.sol", "solidity_code": _SOLIDITY_ADDR_THIS},
     "env": {"PI_DELEGATECALL_SELF_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "A.sol", "solidity_code": _SOLIDITY_ADDR_THIS},
     "env": {"PI_DELEGATECALL_SELF_STRICT_MODE": "true"}},
]
