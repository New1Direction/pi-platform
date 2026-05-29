"""Parity spec for PiExternalContractGuard.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiExternalContractGuard"

_mod = load_py_agent("pi_external_contract_guard.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiExternalContractGuard()
    out = agent.audit_external(_mod.ExternalContractGuardInput(**data))
    return out.model_dump()


# A clean contract. NOTE on the original agent's Mode-1 quirk: the assignment
# regex looks for the *parameter name* on the LHS of `=` (i.e. `param = ...`),
# not `stateVar = param`. Here the param `owner` is reassigned but an
# `address(0)` check is present, so Mode 1 does not fire. The transfer is wrapped
# in require(), so Mode 2 does not fire either.
_SAFE = "\n".join(
    [
        "contract Vault {",
        "    address owner;",
        "    function setOwner(address owner) public {",
        "        require(owner != address(0));",
        "        owner = resolve();",
        "    }",
        "    function payout(address to, uint amt) public {",
        "        require(token.transfer(to, amt));",
        "    }",
        "}",
    ]
)

# Mode 1 only: the param `owner` is reassigned (`owner = resolve()`) with no
# address(0)/0x0 validation -> vulnerable_functions=['setOwner'], REJECTED.
_UNCHECKED_SETTER = "\n".join(
    [
        "contract Bad {",
        "    function setOwner(address owner) public {",
        "        owner = resolve();",
        "    }",
        "}",
    ]
)

# Mode 2 only: raw lowercase ERC-20 transfer( with no safeTransfer/require(/
# assert( -> interface warning finding, but NOT a vulnerable_function (secure).
_RAW_TRANSFER = "\n".join(
    [
        "contract Pay {",
        "    function payout(address to, uint amt) public {",
        "        token.transfer(to, amt);",
        "    }",
        "}",
    ]
)

# Both modes in the same function: param reassigned without address(0) check
# (Mode 1) AND a raw transfer( (Mode 2).
_BOTH = "\n".join(
    [
        "contract Mix {",
        "    function configure(address s, uint amt) public {",
        "        s = derive();",
        "        token.transfer(s, amt);",
        "    }",
        "}",
    ]
)

# Constructor / fallback keyword handling plus a declaration-only function
# (ends with ';' before '{') which must be skipped by the extractor. The
# fallback body has a lowercase raw transfer( -> Mode 2 interface warning.
_KEYWORDS = "\n".join(
    [
        "contract Kw {",
        "    address impl;",
        "    constructor(address _impl) {",
        "        impl = _impl;",
        "    }",
        "    function ghost() external;",
        "    fallback() external payable {",
        "        token.transfer(msg.sender, 1);",
        "    }",
        "}",
    ]
)

# Comments must be stripped before assignment detection: the param reassignment
# is inside a line comment so Mode 1 should NOT fire even though the param
# matches the address-parameter regex on the raw body.
_COMMENTED = "\n".join(
    [
        "contract Cmt {",
        "    function setOwner(address owner) public {",
        "        // owner = resolve(); this is just documentation",
        "        doNothing();",
        "    }",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "Vault.sol", "solidity_code": _SAFE}},
    {"input": {"file_path": "Bad.sol", "solidity_code": _UNCHECKED_SETTER}},
    {"input": {"file_path": "Pay.sol", "solidity_code": _RAW_TRANSFER}},
    {"input": {"file_path": "Mix.sol", "solidity_code": _BOTH}},
    {"input": {"file_path": "Kw.sol", "solidity_code": _KEYWORDS}},
    {"input": {"file_path": "Cmt.sol", "solidity_code": _COMMENTED}},
    {"input": {"file_path": "empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Bad.sol", "solidity_code": _UNCHECKED_SETTER, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Bad.sol", "solidity_code": _UNCHECKED_SETTER},
     "env": {"PI_EXTERNAL_STRICT_MODE": "false"}},
    {"input": {"file_path": "Bad.sol", "solidity_code": _UNCHECKED_SETTER},
     "env": {"PI_EXTERNAL_STRICT_MODE": "true"}},
]
