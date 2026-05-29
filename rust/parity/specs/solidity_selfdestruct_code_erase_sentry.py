"""Parity spec for PiSoliditySelfdestructCodeEraseSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSoliditySelfdestructCodeEraseSentry"

_mod = load_py_agent("pi_solidity_selfdestruct_code_erase_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSoliditySelfdestructCodeEraseSentry()
    out = agent.audit_selfdestruct_usage(_mod.SelfdestructCodeEraseInput(**data))
    return out.model_dump()


# Clean: a function with no selfdestruct/suicide -> PASSED.
_SECURE = "contract C { function safe() public { x = 1; } }"
# selfdestruct invocation in a function body -> flagged.
_SELFDESTRUCT = "contract C { function kill() public onlyOwner { selfdestruct(payable(owner)); } }"
# deprecated `suicide` alias -> flagged.
_SUICIDE = "contract C { function destroy() external { suicide(owner); } }"
# Multiple functions, only some vulnerable. Spans multiple lines so the
# `[\\s\\S]*?` body group must match across newlines.
_MULTI = "\n".join(
    [
        "contract Vault {",
        "    function deposit() public payable {",
        "        balances[msg.sender] += msg.value;",
        "    }",
        "    function nuke(address target) public {",
        "        selfdestruct(payable(target));",
        "    }",
        "    function legacyKill() public {",
        "        suicide(owner);",
        "    }",
        "}",
    ]
)
# `selfdestruct` mentioned only in a comment OUTSIDE any function body. The
# regex only inspects matched function bodies, so this should NOT flag.
_COMMENT_ONLY = "// selfdestruct is dangerous\ncontract C { function ok() public { return; } }"
# Function with args captured by group 2 but body is clean.
_WITH_ARGS = "contract C { function transfer(address to, uint256 amt) public { _move(to, amt); } }"

SAMPLES = [
    # clean / passing
    {"input": {"file_path": "C.sol", "solidity_code": _SECURE}},
    # selfdestruct path
    {"input": {"file_path": "C.sol", "solidity_code": _SELFDESTRUCT}},
    # suicide path
    {"input": {"file_path": "C.sol", "solidity_code": _SUICIDE}},
    # multi-function mixed
    {"input": {"file_path": "Vault.sol", "solidity_code": _MULTI}},
    # selfdestruct only in comment, not a function body
    {"input": {"file_path": "C.sol", "solidity_code": _COMMENT_ONLY}},
    # function with args, clean body
    {"input": {"file_path": "C.sol", "solidity_code": _WITH_ARGS}},
    # empty source
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    # explicit non-default check_level (does not affect logic)
    {"input": {"file_path": "C.sol", "solidity_code": _SELFDESTRUCT, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _SELFDESTRUCT},
     "env": {"PI_SELFDESTRUCT_CODE_ERASE_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "C.sol", "solidity_code": _SELFDESTRUCT},
     "env": {"PI_SELFDESTRUCT_CODE_ERASE_STRICT_MODE": "true"}},
]
