"""Parity spec for PiUninitializedStateSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiUninitializedStateSentry"

_mod = load_py_agent("pi_uninitialized_state_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiUninitializedStateSentry()
    out = agent.audit_uninitialized(_mod.UninitializedInput(**data))
    return out.model_dump()


# A fully-initialized contract: state var assigned in constructor -> PASSED.
_CLEAN = "\n".join(
    [
        "contract C {",
        "  address public owner;",
        "  constructor() { owner = msg.sender; }",
        "}",
    ]
)

# Uninitialized storage variable, never assigned anywhere -> flagged.
_UNINIT = "\n".join(
    [
        "contract C {",
        "  address public owner;",
        "  uint256 total;",
        "}",
    ]
)

# Inline-initialized at declaration site (var = value elsewhere in code).
_INLINE_INIT = "\n".join(
    [
        "contract C {",
        "  uint256 public total;",
        "  function bump() public { total = 5; }",
        "}",
    ]
)

# constant/immutable-prefixed names are skipped by the (dropped) lookahead.
_CONSTANT_SKIP = "\n".join(
    [
        "contract C {",
        "  address constantThing;",
        "  bytes32 immutableHash;",
        "}",
    ]
)

# Upgradeable proxy: initialize() without the 'initializer' modifier.
_UPGRADE_NO_MODIFIER = "\n".join(
    [
        "contract C is Upgradeable {",
        "  address public owner;",
        "  function initialize() public { owner = msg.sender; }",
        "}",
    ]
)

# Upgradeable ERC20: initialize() missing __ERC20_init() parent call.
_UPGRADE_ERC20 = "\n".join(
    [
        "contract C is ERC20Upgradeable {",
        "  function initialize() public initializer { x = 1; }",
        "  uint256 x;",
        "}",
    ]
)

# Comments must be stripped before scanning (// and /* */).
_COMMENTS = "\n".join(
    [
        "contract C {",
        "  // address public ghost; should be ignored",
        "  /* uint256 blockComment; */",
        "  address public real;",
        "  constructor() { real = msg.sender; }",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "C.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNINIT}},
    {"input": {"file_path": "C.sol", "solidity_code": _INLINE_INIT}},
    {"input": {"file_path": "C.sol", "solidity_code": _CONSTANT_SKIP}},
    {"input": {"file_path": "C.sol", "solidity_code": _UPGRADE_NO_MODIFIER}},
    {"input": {"file_path": "C.sol", "solidity_code": _UPGRADE_ERC20}},
    {"input": {"file_path": "C.sol", "solidity_code": _COMMENTS}},
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNINIT, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "C.sol", "solidity_code": _UNINIT},
     "env": {"PI_UNINITIALIZED_STRICT_MODE": "false"}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNINIT},
     "env": {"PI_UNINITIALIZED_STRICT_MODE": "true"}},
]
