"""Parity spec for PiSolidityDirtyMemorySentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityDirtyMemorySentry"

_mod = load_py_agent("pi_solidity_dirty_memory_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityDirtyMemorySentry()
    out = agent.audit_dirty_memory(_mod.DirtyMemoryInput(**data))
    return out.model_dump()


# A clean contract: assembly + mstore but loads the free memory pointer 0x40.
_SAFE_FREE_PTR = (
    "contract C {\n"
    "  function safe() public pure {\n"
    "    assembly { let ptr := mload(0x40) mstore(0x80, 1) }\n"
    "  }\n"
    "}"
)

# No assembly at all -> never flagged.
_NO_ASSEMBLY = (
    "contract C {\n"
    "  function transfer(address to, uint amt) public { balances[to] += amt; }\n"
    "}"
)

# assembly + mstore to absolute hex offset 0x80, no mload(0x40) -> vulnerable.
_DIRTY_HEX = (
    "contract C {\n"
    "  function bad() public { assembly { mstore(0x80, caller()) } }\n"
    "}"
)

# assembly + mstore to absolute decimal offset 128, no mload(0x40) -> vulnerable.
_DIRTY_DEC = (
    "contract C {\n"
    "  function badDec() public { assembly { mstore(128, 7) } }\n"
    "}"
)

# assembly + mstore to 0x00 and 0x20. NOTE: `0x20` actually MATCHES the
# absolute-dynamic regex branch `0x[89a-fA-F0-9]{2,}` (two hex digits 2,0), so
# this is FLAGGED by the agent. Kept as a sample to lock the regex's real
# (perhaps surprising) hex-class behaviour into the parity harness.
_SCRATCH_ONLY = (
    "contract C {\n"
    "  function scratch() public { assembly { mstore(0x00, 1) mstore(0x20, 2) } }\n"
    "}"
)

# Two functions: one safe (loads 0x40), one dirty -> only the dirty one flagged.
_MIXED = (
    "contract C {\n"
    "  function ok() public { assembly { let p := mload(0x40) mstore(0x80, p) } }\n"
    "  function evil() public { assembly { mstore(0x100, 9) } }\n"
    "}"
)

SAMPLES = [
    # clean: free-memory pointer is loaded
    {"input": {"file_path": "C.sol", "solidity_code": _SAFE_FREE_PTR}},
    # clean: no assembly
    {"input": {"file_path": "C.sol", "solidity_code": _NO_ASSEMBLY}},
    # vulnerable: hex absolute offset
    {"input": {"file_path": "C.sol", "solidity_code": _DIRTY_HEX}},
    # vulnerable: decimal absolute offset
    {"input": {"file_path": "C.sol", "solidity_code": _DIRTY_DEC}},
    # clean: only scratch space writes
    {"input": {"file_path": "C.sol", "solidity_code": _SCRATCH_ONLY}},
    # mixed: only the dirty function is flagged
    {"input": {"file_path": "C.sol", "solidity_code": _MIXED}},
    # edge: empty source
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    # check_level override (does not affect logic, exercises the field)
    {"input": {"file_path": "C.sol", "solidity_code": _DIRTY_HEX, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _DIRTY_HEX},
     "env": {"PI_DIRTY_MEMORY_STRICT_MODE": "false"}},
    # strict env -> REJECTED path
    {"input": {"file_path": "C.sol", "solidity_code": _DIRTY_HEX},
     "env": {"PI_DIRTY_MEMORY_STRICT_MODE": "true"}},
]
