"""Parity spec for PiSolidityReentrancyGuardOverlapSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityReentrancyGuardOverlapSentry"

_mod = load_py_agent("pi_solidity_reentrancy_guard_overlap_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityReentrancyGuardOverlapSentry()
    out = agent.audit_reentrancy_overlap(_mod.ReentrancyGuardOverlapInput(**data))
    return out.model_dump()


# Clean: a single reentrancy guard is fine (no overlap).
_CLEAN = "\n".join(
    [
        "contract Vault {",
        "    function withdraw(uint amount) external nonReentrant {",
        "        balances[msg.sender] -= amount;",
        "    }",
        "}",
    ]
)

# Two overlapping guards on one function -> flagged.
_OVERLAP_TWO = "\n".join(
    [
        "contract Vault {",
        "    function withdraw(uint amount) external nonReentrant lock {",
        "        balances[msg.sender] -= amount;",
        "    }",
        "}",
    ]
)

# Three overlapping guards -> flagged, list order follows keyword definition order.
_OVERLAP_THREE = "\n".join(
    [
        "contract Vault {",
        "    function drain() public nonReentrant mutex prevReentrant {",
        "        selfdestruct(payable(msg.sender));",
        "    }",
        "}",
    ]
)

# Multiple functions: one clean, one overlapping.
_MIXED = "\n".join(
    [
        "contract Mixed {",
        "    function safe() external nonReentrant {",
        "        x = 1;",
        "    }",
        "    function unsafe() external noReentrancy lock {",
        "        y = 2;",
        "    }",
        "}",
    ]
)

# Keyword appears only as a substring (no word boundary) -> NOT matched.
# 'lock' inside 'lockbox' / 'unlockable' must not trigger a finding.
_SUBSTRING_DECOY = "\n".join(
    [
        "contract Decoy {",
        "    function f() external lockbox unlockable nonReentrant {",
        "        z = 3;",
        "    }",
        "}",
    ]
)

# No function declarations at all.
_NO_FUNCS = "\n".join(
    [
        "contract Empty {",
        "    uint256 public total;",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Vault.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _OVERLAP_TWO}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _OVERLAP_THREE}},
    {"input": {"file_path": "Mixed.sol", "solidity_code": _MIXED}},
    {"input": {"file_path": "Decoy.sol", "solidity_code": _SUBSTRING_DECOY}},
    {"input": {"file_path": "Empty.sol", "solidity_code": _NO_FUNCS}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _OVERLAP_TWO, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Vault.sol", "solidity_code": _OVERLAP_TWO},
     "env": {"PI_REENTRANCY_GUARD_OVERLAP_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "Vault.sol", "solidity_code": _OVERLAP_TWO},
     "env": {"PI_REENTRANCY_GUARD_OVERLAP_STRICT_MODE": "true"}},
]
