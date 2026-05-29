"""Parity spec for PiSolidityTransientStorageReentrancySentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityTransientStorageReentrancySentry"

_mod = load_py_agent("pi_solidity_transient_storage_reentrancy_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityTransientStorageReentrancySentry()
    out = agent.audit_transient_reentrancy(
        _mod.TransientStorageReentrancyInput(**data)
    )
    return out.model_dump()


# Clean: tstore is explicitly cleared back to 0 -> secure.
_CLEARED = "\n".join(
    [
        "contract Safe {",
        "    function deposit() public {",
        "        assembly { tstore(1, 9) tstore(1, 0) }",
        "    }",
        "}",
    ]
)

# Vulnerable: tstore written but never reset -> flagged.
_UNCLEARED = "\n".join(
    [
        "contract Bad {",
        "    function withdraw() external {",
        "        assembly { tstore(2, 7) }",
        "    }",
        "}",
    ]
)

# Vulnerable cleared with 0x0 hex literal -> secure.
_CLEARED_HEX = "\n".join(
    [
        "contract HexSafe {",
        "    function pull() public {",
        "        assembly { tstore(slot, 5) tstore(slot, 0x0) }",
        "    }",
        "}",
    ]
)

# No tstore at all -> secure (no transient storage usage).
_NO_TSTORE = "\n".join(
    [
        "contract Plain {",
        "    function add() public returns (uint) {",
        "        uint y = 5;",
        "        return y;",
        "    }",
        "}",
    ]
)

# Multiple functions: one safe (cleared), one vulnerable.
_MIXED = "\n".join(
    [
        "contract Mixed {",
        "    function ok() public {",
        "        assembly { tstore(0, 1) tstore(0, 0) }",
        "    }",
        "    function leaky(uint x) external returns (bool) {",
        "        assembly { tstore(3, x) }",
        "    }",
        "}",
    ]
)

# tstore cleared on a different slot than it was written -> still 'cleared' per
# the agent's logic (any tstore(_, 0) marks the whole function cleared).
_CLEAR_OTHER_SLOT = "\n".join(
    [
        "contract Partial {",
        "    function mixedSlots() public {",
        "        assembly { tstore(1, 9) tstore(7, 0) }",
        "    }",
        "}",
    ]
)


SAMPLES = [
    {"input": {"file_path": "Safe.sol", "solidity_code": _CLEARED}},
    {"input": {"file_path": "Bad.sol", "solidity_code": _UNCLEARED}},
    {"input": {"file_path": "HexSafe.sol", "solidity_code": _CLEARED_HEX}},
    {"input": {"file_path": "Plain.sol", "solidity_code": _NO_TSTORE}},
    {"input": {"file_path": "Mixed.sol", "solidity_code": _MIXED}},
    {"input": {"file_path": "Partial.sol", "solidity_code": _CLEAR_OTHER_SLOT}},
    # empty / edge input
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    # explicit non-default check_level
    {"input": {"file_path": "Bad.sol", "solidity_code": _UNCLEARED, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Bad.sol", "solidity_code": _UNCLEARED},
     "env": {"PI_TRANSIENT_REENTRANCY_STRICT_MODE": "false"}},
    # strict env explicitly -> REJECTED path
    {"input": {"file_path": "Bad.sol", "solidity_code": _UNCLEARED},
     "env": {"PI_TRANSIENT_REENTRANCY_STRICT_MODE": "true"}},
]
