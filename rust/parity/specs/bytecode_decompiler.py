"""Parity spec for PiBytecodeDecompiler.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiBytecodeDecompiler"

_mod = load_py_agent("pi_bytecode_decompiler.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiBytecodeDecompiler()
    out = agent.audit_bytecode(_mod.BytecodeDecompilerInput(**data))
    return out.model_dump()


# --- Mode 2: Solidity inline assembly samples ---
_CLEAN = "function ok() public { assembly { let x := mload(0x40) } }"
_SELFDESTRUCT = "function nuke() public { assembly { selfdestruct(0) } }"
_SUICIDE = "function legacy() public { assembly { suicide(0) } }"
_DELEGATE_UNSAFE = (
    "function p() public { assembly { let r := delegatecall(gas(), impl, 0, 0, 0, 0) } }"
)
_DELEGATE_SAFE = (
    "bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;\n"
    "function p() public { assembly { let r := delegatecall(gas(), impl, 0, 0, 0, 0) } }"
)
# mstore to scratch space (below 0x40) while 0x40 also present -> optimization warning
_SCRATCH = "function s() public { assembly { mstore(0x20, 1) let p := mload(0x40) } }"
# multiple assembly blocks across lines + a comment that should be stripped
_MULTI = "\n".join(
    [
        "contract C {",
        "    // assembly { selfdestruct(0) }  <- comment, must be ignored",
        "    function a() public { assembly { selfdestruct(0) } }",
        "    function b() public { assembly { let r := delegatecall(gas(),i,0,0,0,0) } }",
        "}",
    ]
)

# --- Mode 1: raw EVM bytecode samples ---
_RAW_FF = "0x60606040ff52"          # contains selfdestruct opcode 0xff
_RAW_F4 = "60606040f45260aa"        # no 0x prefix, contains delegatecall 0xf4
_RAW_BOTH = "0xfff4aabbccddee"      # contains both ff and f4
_RAW_CLEAN = "0x60606040526001"     # no ff / f4 opcodes

SAMPLES = [
    # clean solidity -> PASSED (strict mode irrelevant to output)
    {"input": {"file_path": "c.sol", "solidity_code": _CLEAN}},
    # selfdestruct in assembly, strict -> REJECTED
    {"input": {"file_path": "c.sol", "solidity_code": _SELFDESTRUCT},
     "env": {"PI_BYTECODE_STRICT_MODE": "true"}},
    # suicide (legacy selfdestruct), strict -> REJECTED
    {"input": {"file_path": "c.sol", "solidity_code": _SUICIDE},
     "env": {"PI_BYTECODE_STRICT_MODE": "true"}},
    # unsafe delegatecall, strict -> REJECTED
    {"input": {"file_path": "c.sol", "solidity_code": _DELEGATE_UNSAFE},
     "env": {"PI_BYTECODE_STRICT_MODE": "true"}},
    # delegatecall guarded by EIP-1967 slot reference -> PASSED
    {"input": {"file_path": "c.sol", "solidity_code": _DELEGATE_SAFE}},
    # mstore scratch-space optimization warning (still secure -> PASSED)
    {"input": {"file_path": "c.sol", "solidity_code": _SCRATCH}},
    # multi-line, comment-stripping, two assembly blocks, strict -> REJECTED
    {"input": {"file_path": "c.sol", "solidity_code": _MULTI},
     "env": {"PI_BYTECODE_STRICT_MODE": "true"}},
    # raw bytecode with selfdestruct opcode (0xff), strict -> REJECTED
    {"input": {"file_path": "b.bin", "solidity_code": _RAW_FF},
     "env": {"PI_BYTECODE_STRICT_MODE": "true"}},
    # raw bytecode with delegatecall opcode (0xf4), no prefix, strict -> REJECTED
    {"input": {"file_path": "b.bin", "solidity_code": _RAW_F4},
     "env": {"PI_BYTECODE_STRICT_MODE": "true"}},
    # raw bytecode with both opcodes, strict -> REJECTED (two findings)
    {"input": {"file_path": "b.bin", "solidity_code": _RAW_BOTH},
     "env": {"PI_BYTECODE_STRICT_MODE": "true"}},
    # clean raw bytecode -> PASSED
    {"input": {"file_path": "b.bin", "solidity_code": _RAW_CLEAN}},
    # empty input -> Mode 2, no blocks -> PASSED
    {"input": {"file_path": "e.sol", "solidity_code": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "c.sol", "solidity_code": _SELFDESTRUCT},
     "env": {"PI_BYTECODE_STRICT_MODE": "false"}},
]
