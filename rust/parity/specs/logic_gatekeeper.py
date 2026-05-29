"""Parity spec for PiLogicGatekeeper.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}

NOTE: this agent reads `PI_LOGIC_STRICT_MODE`, falling back to a
`.antigravitycli/config.json` file (default True) only when the env var is
unset. To keep parity deterministic and independent of any host config file,
every sample below pins `PI_LOGIC_STRICT_MODE` explicitly.
"""
from _util import load_py_agent

RUST_NAME = "PiLogicGatekeeper"

_mod = load_py_agent("pi_logic_gatekeeper.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiLogicGatekeeper()
    out = agent.audit_logic(_mod.LogicGatekeeperInput(**data))
    return out.model_dump()


# --- Clean / passing contract --------------------------------------------
_CLEAN = "function transfer(address to, uint amount) public { balances[to] += amount; }"

# --- Empty modifier missing the `_;` merge wildcard ----------------------
_EMPTY_MODIFIER = "modifier onlyOwner() { require(msg.sender == owner); }"

# --- Good modifier WITH `_;` -> not flagged ------------------------------
_GOOD_MODIFIER = "modifier onlyOwner() { require(msg.sender == owner); _; }"

# --- Unsigned tautology  `uint x >= 0` -----------------------------------
_TAUTOLOGY_GE = "function check(uint amount) public { require(amount >= 0); }"

# --- Unsigned tautology  `uint x < 0` ------------------------------------
_TAUTOLOGY_LT = "function check(uint256 bal) public { if (bal < 0) { revert(); } }"

# --- Unreachable dead code following a return ----------------------------
_DEAD_CODE = "\n".join(
    [
        "function compute() public returns (uint) {",
        "    return 1; foo = 2;",
        "}",
    ]
)

# --- Comment-only modifier body -> cleaned body has no `_;` -> flagged ----
_COMMENT_MODIFIER = "\n".join(
    [
        "modifier gate() {",
        "    // _; this wildcard is only inside a comment",
        "    require(true);",
        "}",
    ]
)

# --- Multiple findings in one contract -----------------------------------
_MULTI = "\n".join(
    [
        "modifier onlyAdmin() { require(isAdmin); }",
        "function withdraw(uint amt) public onlyAdmin {",
        "    require(amt >= 0);",
        "    return; cleanup();",
        "}",
        "function safe() public { _; }",
    ]
)

SAMPLES = [
    {"input": {"file_path": "C.sol", "solidity_code": _CLEAN},
     "env": {"PI_LOGIC_STRICT_MODE": "true"}},
    {"input": {"file_path": "C.sol", "solidity_code": _EMPTY_MODIFIER},
     "env": {"PI_LOGIC_STRICT_MODE": "true"}},
    {"input": {"file_path": "C.sol", "solidity_code": _GOOD_MODIFIER},
     "env": {"PI_LOGIC_STRICT_MODE": "true"}},
    {"input": {"file_path": "C.sol", "solidity_code": _TAUTOLOGY_GE},
     "env": {"PI_LOGIC_STRICT_MODE": "true"}},
    {"input": {"file_path": "C.sol", "solidity_code": _TAUTOLOGY_LT},
     "env": {"PI_LOGIC_STRICT_MODE": "true"}},
    {"input": {"file_path": "C.sol", "solidity_code": _DEAD_CODE},
     "env": {"PI_LOGIC_STRICT_MODE": "true"}},
    {"input": {"file_path": "C.sol", "solidity_code": _COMMENT_MODIFIER},
     "env": {"PI_LOGIC_STRICT_MODE": "true"}},
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI},
     "env": {"PI_LOGIC_STRICT_MODE": "true"}},
    # empty / edge input
    {"input": {"file_path": "C.sol", "solidity_code": ""},
     "env": {"PI_LOGIC_STRICT_MODE": "true"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _EMPTY_MODIFIER},
     "env": {"PI_LOGIC_STRICT_MODE": "false"}},
    {"input": {"file_path": "C.sol", "solidity_code": _TAUTOLOGY_GE, "check_level": "MEDIUM"},
     "env": {"PI_LOGIC_STRICT_MODE": "false"}},
]
