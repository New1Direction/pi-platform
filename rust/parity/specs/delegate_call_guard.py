"""Parity spec for PiDelegateCallGuard.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDelegateCallGuard"

_mod = load_py_agent("pi_delegate_call_guard.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDelegateCallGuard()
    out = agent.audit_delegatecall(_mod.DelegateCallInput(**data))
    return out.model_dump()


# A clean contract with no delegatecall at all -> PASSED.
_CLEAN = "\n".join(
    [
        "contract Safe {",
        "  uint256 value;",
        "  function ping() public {",
        "    value = 1;",
        "  }",
        "}",
    ]
)

# A single unsafe delegatecall with no EIP-1967 slot -> flagged.
_UNSAFE = "\n".join(
    [
        "contract Vault {",
        "  function exec(address t, bytes memory data) public {",
        "    (bool ok, ) = t.delegatecall(data);",
        "    require(ok);",
        "  }",
        "}",
    ]
)

# Delegatecall guarded by the standard EIP-1967 slot -> compliant proxy, PASSED.
_EIP1967 = "\n".join(
    [
        "contract Proxy {",
        "  function _delegate(address impl) internal {",
        "    bytes32 slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;",
        "    impl.delegatecall(msg.data);",
        "  }",
        "}",
    ]
)

# Constructor with a delegatecall is explicitly skipped -> PASSED.
_CONSTRUCTOR = "\n".join(
    [
        "contract C {",
        "  constructor(address impl) {",
        "    impl.delegatecall(abi.encodeWithSignature('init()'));",
        "  }",
        "}",
    ]
)

# Multiple functions: one safe, two with unsafe delegatecalls (distinct names).
_MULTI = "\n".join(
    [
        "contract Multi {",
        "  function safe() public { x = 1; }",
        "  function a(bytes memory d) public {",
        "    target.delegatecall(d);",
        "  }",
        "  function b(address t, bytes memory d) public {",
        "    t.delegatecall(d);",
        "  }",
        "}",
    ]
)

# Comments hiding a delegatecall: the line comment strips the call, so the body
# no longer contains "delegatecall(" -> PASSED. Exercises the comment-cleaning.
_COMMENTED = "\n".join(
    [
        "contract Commented {",
        "  function exec(bytes memory d) public {",
        "    // target.delegatecall(d);",
        "    x = 1;",
        "  }",
        "}",
    ]
)

# Abstract function declaration (semicolon before brace) -> not a concrete body.
_ABSTRACT = "\n".join(
    [
        "interface I {",
        "  function doThing(bytes memory d) external;",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Safe.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _UNSAFE}},
    {"input": {"file_path": "Proxy.sol", "solidity_code": _EIP1967}},
    {"input": {"file_path": "C.sol", "solidity_code": _CONSTRUCTOR}},
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Commented.sol", "solidity_code": _COMMENTED}},
    {"input": {"file_path": "I.sol", "solidity_code": _ABSTRACT}},
    {"input": {"file_path": "empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _UNSAFE, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Vault.sol", "solidity_code": _UNSAFE},
     "env": {"PI_DELEGATECALL_STRICT_MODE": "false"}},
    # strict env -> REJECTED path
    {"input": {"file_path": "Vault.sol", "solidity_code": _UNSAFE},
     "env": {"PI_DELEGATECALL_STRICT_MODE": "true"}},
]
