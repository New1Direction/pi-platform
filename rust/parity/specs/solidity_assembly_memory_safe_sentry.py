"""Parity spec for PiSolidityAssemblyMemorySafeSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityAssemblyMemorySafeSentry"

_mod = load_py_agent("pi_solidity_assembly_memory_safe_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityAssemblyMemorySafeSentry()
    out = agent.audit_assembly_memory_safe(_mod.AssemblyMemorySafeInput(**data))
    return out.model_dump()


# Clean: assembly marked memory-safe but only reads/writes high memory.
_CLEAN = """contract C {
    function clean(uint256 x) public {
        assembly ("memory-safe") {
            let y := add(x, 1)
            mstore(0x80, y)
        }
    }
}"""

# Vulnerable: mstore to 0x40 (free memory pointer) inside a memory-safe block.
_VULN_FMP = """contract C {
    function bad(uint256 x) internal {
        assembly ("memory-safe") {
            mstore(0x40, x)
        }
    }
}"""

# Vulnerable: mstore8 to 0x00 (scratch space) inside a memory-safe block.
_VULN_SCRATCH = """contract C {
    function scratch() public {
        assembly ("memory-safe") {
            mstore8(0x0, 1)
        }
    }
}"""

# Vulnerable: decimal offset below 128.
_VULN_DECIMAL = """contract C {
    function dec() public {
        assembly ("memory-safe") {
            mstore(96, 7)
        }
    }
}"""

# Two functions: one safe, one vulnerable, exercising the function-block scan.
_MIXED = """contract C {
    function safe(uint256 a) external {
        assembly ("memory-safe") {
            mstore(0x80, a)
        }
    }
    function unsafe(uint256 b) external {
        assembly ("memory-safe") {
            mstore(0x20, b)
        }
    }
}"""

# Assembly block NOT marked memory-safe: writes below 0x80 but should be ignored.
_UNMARKED = """contract C {
    function raw() public {
        assembly {
            mstore(0x00, 1)
        }
    }
}"""

# Memory-safe block with single-quote marker and a write at exactly 0x80 (safe).
_QUOTE_HIGH = """contract C {
    function q() public {
        assembly ('memory-safe') {
            mstore(0x80, 1)
        }
    }
}"""

SAMPLES = [
    {"input": {"file_path": "C.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_FMP}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_SCRATCH}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_DECIMAL}},
    {"input": {"file_path": "C.sol", "solidity_code": _MIXED}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNMARKED}},
    {"input": {"file_path": "C.sol", "solidity_code": _QUOTE_HIGH}},
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_FMP, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_FMP},
     "env": {"PI_ASSEMBLY_MEMORY_SAFE_STRICT_MODE": "false"}},
    {"input": {"file_path": "C.sol", "solidity_code": _VULN_FMP},
     "env": {"PI_ASSEMBLY_MEMORY_SAFE_STRICT_MODE": "true"}},
]
