"""Parity spec for PiSolidityDelegatecallStorageSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityDelegatecallStorageSentry"

_mod = load_py_agent("pi_solidity_delegatecall_storage_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityDelegatecallStorageSentry()
    out = agent.audit_delegatecall_storage(_mod.DelegatecallStorageInput(**data))
    return out.model_dump()


# Clean: delegatecall whose impl target is loaded from a standard EIP-1967 slot.
_SECURE = "\n".join(
    [
        "function _delegate() internal {",
        "    assembly {",
        "        let impl := sload(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc)",
        "        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)",
        "    }",
        "}",
    ]
)

# Vulnerable path 1: delegatecall + assembly + sload from a NON-standard slot.
_NONSTD_SLOT = "\n".join(
    [
        "function _proxy() internal {",
        "    assembly {",
        "        let impl := sload(0x1234)",
        "        let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)",
        "    }",
        "}",
    ]
)

# Vulnerable path 1b: sload from a named (identifier) slot variable, not a hex constant.
_NAMED_SLOT = "\n".join(
    [
        "function forward() public {",
        "    assembly {",
        "        let impl := sload(implementationSlot)",
        "        let ok := delegatecall(gas(), impl, 0, 0, 0, 0)",
        "    }",
        "}",
    ]
)

# Vulnerable path 2: delegatecall in assembly with NO sload pattern at all.
_NO_SLOT = "\n".join(
    [
        "function run() public {",
        "    assembly {",
        "        let ok := delegatecall(gas(), addr, 0, 0, 0, 0)",
        "    }",
        "}",
    ]
)

# Multiple functions: one safe (standard slot), one vulnerable (no slot).
_MULTI = "\n".join(
    [
        "function safe() internal {",
        "    assembly {",
        "        let impl := sload(0xa3f0ad74a5890d8e115a428731304671291891c9d44342144a0b228226348149)",
        "        let r := delegatecall(gas(), impl, 0, 0, 0, 0)",
        "    }",
        "}",
        "function risky() internal {",
        "    assembly {",
        "        let r := delegatecall(gas(), target, 0, 0, 0, 0)",
        "    }",
        "}",
    ]
)

# No delegatecall at all -> secure regardless of assembly usage.
_NO_DELEGATECALL = "\n".join(
    [
        "function readSlot() public view returns (uint256 v) {",
        "    assembly {",
        "        v := sload(0x1234)",
        "    }",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Proxy.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "Proxy.sol", "solidity_code": _NONSTD_SLOT}},
    {"input": {"file_path": "Proxy.sol", "solidity_code": _NAMED_SLOT}},
    {"input": {"file_path": "Proxy.sol", "solidity_code": _NO_SLOT}},
    {"input": {"file_path": "Proxy.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Proxy.sol", "solidity_code": _NO_DELEGATECALL}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Proxy.sol", "solidity_code": _NONSTD_SLOT, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Proxy.sol", "solidity_code": _NO_SLOT},
     "env": {"PI_DELEGATECALL_STORAGE_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "Proxy.sol", "solidity_code": _NO_SLOT},
     "env": {"PI_DELEGATECALL_STORAGE_STRICT_MODE": "true"}},
]
