"""Parity spec for PiShadowedVariableDetector.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiShadowedVariableDetector"

_mod = load_py_agent("pi_shadowed_variable_detector.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiShadowedVariableDetector()
    out = agent.audit_shadowed(_mod.ShadowedVariableInput(**data))
    return out.model_dump()


# Clean contract: state var present but no parameter shadows it; param is used.
_CLEAN = "\n".join(
    [
        "contract C {",
        "    uint256 public total;",
        "    function set(uint256 amount) public {",
        "        total = amount;",
        "    }",
        "}",
    ]
)

# Shadowing: parameter `owner` collides with the state variable `owner`.
_SHADOW = "\n".join(
    [
        "contract C {",
        "    address public owner;",
        "    function rescue(address owner) public {",
        "        owner = msg.sender;",
        "    }",
        "}",
    ]
)

# Unused parameter: `ghost` is declared but never referenced in the body.
_UNUSED = "\n".join(
    [
        "contract C {",
        "    function noop(uint256 ghost) public {",
        "        uint256 x = 1;",
        "    }",
        "}",
    ]
)

# memory/calldata location specifiers + a constant state var that must NOT be
# collected as a shadow target (exercises the negative-lookahead replacement).
_LOCATIONS = "\n".join(
    [
        "contract C {",
        "    bytes32 constant ROLE = keccak256('x');",
        "    string public title;",
        "    function rename(string memory title, bytes calldata data) public {",
        "        title;",
        "    }",
        "}",
    ]
)

# Comments must be stripped before scanning: the shadow only appears in source,
# the unused finding involves a commented-out reference.
_COMMENTS = "\n".join(
    [
        "contract C {",
        "    uint256 public balance; // user balance",
        "    /* block",
        "       comment */",
        "    function deposit(uint256 balance, uint256 unusedFee) public {",
        "        // unusedFee is only mentioned in a comment",
        "        balance = balance + 1;",
        "    }",
        "}",
    ]
)

# Special function kinds: constructor / fallback / receive naming, plus a
# declaration-only function (semicolon before any brace) that is skipped.
_KINDS = "\n".join(
    [
        "contract C {",
        "    address public admin;",
        "    constructor(address admin) {",
        "        admin = msg.sender;",
        "    }",
        "    function abstractFn(uint256 v) external;",
        "    fallback() external {",
        "    }",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "C.sol", "solidity_code": _CLEAN}},
    {"input": {"file_path": "C.sol", "solidity_code": _SHADOW}},
    {"input": {"file_path": "C.sol", "solidity_code": _UNUSED}},
    {"input": {"file_path": "C.sol", "solidity_code": _LOCATIONS}},
    {"input": {"file_path": "C.sol", "solidity_code": _COMMENTS}},
    {"input": {"file_path": "C.sol", "solidity_code": _KINDS}},
    {"input": {"file_path": "C.sol", "solidity_code": ""}},
    {"input": {"file_path": "C.sol", "solidity_code": _SHADOW, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "C.sol", "solidity_code": _SHADOW},
     "env": {"PI_SHADOW_STRICT_MODE": "false"}},
    {"input": {"file_path": "C.sol", "solidity_code": _SHADOW},
     "env": {"PI_SHADOW_STRICT_MODE": "true"}},
]
