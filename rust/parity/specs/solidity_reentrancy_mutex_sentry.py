"""Parity spec for PiSolidityReentrancyMutexSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityReentrancyMutexSentry"

_mod = load_py_agent("pi_solidity_reentrancy_mutex_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityReentrancyMutexSentry()
    out = agent.audit_mutex(_mod.MutexSentryInput(**data))
    return out.model_dump()


# Clean contract: uses standardized nonReentrant modifier, no custom bool lock.
_CLEAN = "\n".join(
    [
        "contract Vault {",
        "    function withdraw() external nonReentrant {",
        "        (bool ok, ) = msg.sender.call{value: 1}('');",
        "        require(ok);",
        "    }",
        "}",
    ]
)

# Custom boolean mutex declared AND manually toggled -> flagged.
_VULN_LOCKED = "\n".join(
    [
        "contract Vault {",
        "    bool private locked;",
        "    function withdraw() external {",
        "        require(!locked);",
        "        locked = true;",
        "        msg.sender.call{value: 1}('');",
        "        locked = false;",
        "    }",
        "}",
    ]
)

# Custom boolean mutex using the `inSwap` name variant.
_VULN_INSWAP = "\n".join(
    [
        "contract Token {",
        "    bool inSwap;",
        "    function swap() internal {",
        "        inSwap = true;",
        "        _doSwap();",
        "        inSwap = false;",
        "    }",
        "}",
    ]
)

# Custom boolean mutex using the `reentrancyLock` name variant + `public`.
_VULN_REENTRANCY = "\n".join(
    [
        "contract Pool {",
        "    bool public reentrancyLock;",
        "    function f() external {",
        "        reentrancyLock = true;",
        "    }",
        "}",
    ]
)

# Declaration present but NEVER toggled (no `= true/false`) -> NOT flagged.
_DECL_NO_TOGGLE = "\n".join(
    [
        "contract Vault {",
        "    bool private locked;",
        "    function reset() external {",
        "        delete locked;",
        "    }",
        "}",
    ]
)

# Toggle present but NO matching `bool` declaration -> NOT flagged (decl gate).
_TOGGLE_NO_DECL = "\n".join(
    [
        "contract Vault {",
        "    function f() external {",
        "        locked = true;",
        "    }",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Vault.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_LOCKED}},
    {"input": {"file_path": "Token.sol", "solidity_code": _VULN_INSWAP}},
    {"input": {"file_path": "Pool.sol", "solidity_code": _VULN_REENTRANCY}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _DECL_NO_TOGGLE}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _TOGGLE_NO_DECL}},
    {"input": {"file_path": "empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_LOCKED, "check_level": "MEDIUM"}},
    # strict env explicitly true -> REJECTED_MUTEX_RISK
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_LOCKED},
     "env": {"PI_MUTEX_SENTRY_STRICT_MODE": "true"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Vault.sol", "solidity_code": _VULN_LOCKED},
     "env": {"PI_MUTEX_SENTRY_STRICT_MODE": "false"}},
]
