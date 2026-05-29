"""Parity spec for PiCentralizationSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiCentralizationSentry"

_mod = load_py_agent("pi_centralization_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiCentralizationSentry()
    out = agent.audit_centralization(_mod.CentralizationInput(**data))
    return out.model_dump()


# Clean contract: no admin functions, nothing to flag.
_CLEAN = (
    "contract Token {\n"
    "    function transfer(address to, uint amount) public {\n"
    "        balances[to] += amount;\n"
    "    }\n"
    "}\n"
)

# Centralization risk: privileged mint behind onlyOwner with no timelock/multisig.
_MINT_RISK = (
    "contract Token {\n"
    "    function mint(address to, uint amt) public onlyOwner {\n"
    "        _mint(to, amt);\n"
    "    }\n"
    "}\n"
)

# Admin pause behind onlyAdmin (different action keyword + different modifier).
_PAUSE_RISK = (
    "function pauseAll() external onlyAdmin {\n"
    "    paused = true;\n"
    "}\n"
)

# Admin withdraw behind onlyRole, but body mentions a safe keyword (timelock)
# so Mode 1 must NOT flag it.
_WITHDRAW_SAFE = (
    "function withdrawFees() public onlyRole(ADMIN) {\n"
    "    require(block.timestamp > timelock, 'wait');\n"
    "    _withdraw();\n"
    "}\n"
)

# Mode 2: timelock setter that compares delay with '<' and no secure floor const.
_TIMELOCK_WARN = (
    "function setTimelockDelay(uint d) public onlyOwner {\n"
    "    require(d < 3600, 'delay too small');\n"
    "    minDelay = d;\n"
    "}\n"
)

# Mode 2: delay setter with a recognized secure floor (172800) -> no warning.
_TIMELOCK_OK = (
    "function updateDelay(uint d) public {\n"
    "    require(d < 172800);\n"
    "    delayValue = d;\n"
    "}\n"
)

# Comment-stripping: safe keyword only appears in a comment, so it is removed by
# the cleaner and the function is still flagged as centralized.
_COMMENT_STRIP = (
    "function setFee(uint f) public onlyOwner {\n"
    "    // this should use a timelock someday\n"
    "    fee = f; /* multisig planned */\n"
    "}\n"
)

# Multiple functions and a declaration-only (semicolon, no body) that is skipped.
_MULTI = (
    "interface I { function mint(address a, uint b) external; }\n"
    "contract C {\n"
    "    constructor() { owner = msg.sender; }\n"
    "    function mintTo(address to) public onlyOwner { _mint(to); }\n"
    "    function safeMint(address to) public onlyOwner {\n"
    "        require(approved, 'need multisig');\n"
    "        _mint(to);\n"
    "    }\n"
    "}\n"
)

SAMPLES = [
    {"input": {"file_path": "C.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "C.sol", "solidity_code": _MINT_RISK}},
    {"input": {"file_path": "C.sol", "solidity_code": _PAUSE_RISK}},
    {"input": {"file_path": "C.sol", "solidity_code": _WITHDRAW_SAFE}},
    {"input": {"file_path": "C.sol", "solidity_code": _TIMELOCK_WARN}},
    {"input": {"file_path": "C.sol", "solidity_code": _TIMELOCK_OK}},
    {"input": {"file_path": "C.sol", "solidity_code": _COMMENT_STRIP}},
    {"input": {"file_path": "C.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _MINT_RISK},
     "env": {"PI_CENTRALIZATION_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED
    {"input": {"file_path": "C.sol", "solidity_code": _MINT_RISK},
     "env": {"PI_CENTRALIZATION_STRICT_MODE": "true"}},
]
