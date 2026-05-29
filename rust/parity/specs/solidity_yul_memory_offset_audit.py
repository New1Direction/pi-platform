"""Parity spec for PiSolidityYulMemoryOffsetAudit.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityYulMemoryOffsetAudit"

_mod = load_py_agent("pi_solidity_yul_memory_offset_audit.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityYulMemoryOffsetAudit()
    out = agent.audit_yul_memory(_mod.YulMemoryOffsetInput(**data))
    return out.model_dump()


# A function with no assembly at all -> clean / PASSED.
_CLEAN = "function transfer(address to, uint amount) public { balances[to] += amount; }"

# Assembly that only writes to scratch space 0x00 (not flagged).
_SCRATCH = (
    "function hashIt(uint a) internal pure returns (bytes32 r) {\n"
    "    assembly {\n"
    "        mstore(0x00, a)\n"
    "        r := keccak256(0x00, 0x20)\n"
    "    }\n"
    "}"
)

# Assembly that overwrites the free memory pointer at 0x40 -> vulnerable.
_FMP_HEX = (
    "function corrupt() public {\n"
    "    assembly {\n"
    "        mstore(0x40, 0x80)\n"
    "    }\n"
    "}"
)

# Same vulnerability but expressed with a decimal offset (64 == 0x40).
_FMP_DEC = (
    "function corruptDec() public {\n"
    "    assembly {\n"
    "        mstore(64, 0x80)\n"
    "    }\n"
    "}"
)

# Multiple functions: one clean, one scratch-only, one vulnerable.
_MULTI = "\n".join(
    [
        "function safeAdd(uint a, uint b) public pure returns (uint) { return a + b; }",
        "function scratchOnly() internal { assembly { mstore(0x20, 5) } }",
        "function evil() external { assembly { mstore(0x40, 0xff) } }",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Clean.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "Scratch.sol", "solidity_code": _SCRATCH}},
    {"input": {"file_path": "Corrupt.sol", "solidity_code": _FMP_HEX}},
    {"input": {"file_path": "CorruptDec.sol", "solidity_code": _FMP_DEC}},
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Corrupt.sol", "solidity_code": _FMP_HEX, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Corrupt.sol", "solidity_code": _FMP_HEX},
     "env": {"PI_YUL_MEMORY_OFFSET_STRICT_MODE": "false"}},
    {"input": {"file_path": "Corrupt.sol", "solidity_code": _FMP_HEX},
     "env": {"PI_YUL_MEMORY_OFFSET_STRICT_MODE": "true"}},
]
