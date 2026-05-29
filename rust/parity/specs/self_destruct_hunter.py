"""Parity spec for PiSelfDestructHunter.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSelfDestructHunter"

_mod = load_py_agent("pi_self_destruct_hunter.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSelfDestructHunter()
    out = agent.audit_selfdestruct(_mod.SelfDestructHunterInput(**data))
    return out.model_dump()


# Unauthorized selfdestruct -> vulnerable (REJECTED in strict mode).
_UNAUTH = "\n".join(
    [
        "contract Vault {",
        "  function kill() public {",
        "    selfdestruct(payable(msg.sender));",
        "  }",
        "}",
    ]
)

# Authorized via onlyOwner modifier, but NO pause mechanism -> secure,
# emits a decommissioning warning.
_AUTH_NO_PAUSE = "\n".join(
    [
        "contract Vault {",
        "  function kill() public onlyOwner {",
        "    selfdestruct(payable(owner));",
        "  }",
        "}",
    ]
)

# Authorized AND has a pause mechanism -> secure, no findings at all.
_AUTH_WITH_PAUSE = "\n".join(
    [
        "contract Vault {",
        "  bool public paused;",
        "  function kill() public onlyOwner {",
        "    selfdestruct(payable(owner));",
        "  }",
        "}",
    ]
)

# Authorized via owner-equality require (lowercased match) + expire keyword.
_AUTH_REQUIRE = "\n".join(
    [
        "contract Vault {",
        "  uint public expire;",
        "  function destroy() external {",
        "    require(msg.sender == owner, 'not owner');",
        "    selfdestruct(payable(owner));",
        "  }",
        "}",
    ]
)

# Old-style suicide() with no auth -> vulnerable.
_SUICIDE = "\n".join(
    [
        "contract Legacy {",
        "  function terminate() public {",
        "    suicide(msg.sender);",
        "  }",
        "}",
    ]
)

# selfdestruct hidden inside comments must be ignored (cleaned out).
_COMMENTED = "\n".join(
    [
        "contract Safe {",
        "  function noop() public {",
        "    // selfdestruct(payable(msg.sender));",
        "    /* selfdestruct(owner); */",
        "    uint x = 1;",
        "  }",
        "}",
    ]
)

# Clean contract, no selfdestruct at all.
_CLEAN = "\n".join(
    [
        "contract Token {",
        "  function transfer(address to, uint amt) public returns (bool) {",
        "    return true;",
        "  }",
        "}",
    ]
)

SAMPLES = [
    # clean / passing
    {"input": {"file_path": "Token.sol", "solidity_code": _CLEAN}},
    # vulnerable: unauthorized selfdestruct (strict default -> REJECTED)
    {"input": {"file_path": "Vault.sol", "solidity_code": _UNAUTH}},
    # authorized but no pause mech -> decommissioning warning, still secure
    {"input": {"file_path": "Vault.sol", "solidity_code": _AUTH_NO_PAUSE}},
    # authorized + pause mech -> fully clean
    {"input": {"file_path": "Vault.sol", "solidity_code": _AUTH_WITH_PAUSE}},
    # authorized via require(msg.sender == owner) + expire keyword
    {"input": {"file_path": "Vault.sol", "solidity_code": _AUTH_REQUIRE}},
    # legacy suicide() unauthorized -> vulnerable
    {"input": {"file_path": "Legacy.sol", "solidity_code": _SUICIDE}},
    # selfdestruct only in comments -> ignored, secure
    {"input": {"file_path": "Safe.sol", "solidity_code": _COMMENTED}},
    # empty / edge input
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Vault.sol", "solidity_code": _UNAUTH},
     "env": {"PI_SELFDESTRUCT_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "Vault.sol", "solidity_code": _UNAUTH},
     "env": {"PI_SELFDESTRUCT_STRICT_MODE": "true"}},
]
