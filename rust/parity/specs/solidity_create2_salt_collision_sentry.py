"""Parity spec for PiSolidityCreate2SaltCollisionSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityCreate2SaltCollisionSentry"

_mod = load_py_agent("pi_solidity_create2_salt_collision_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityCreate2SaltCollisionSentry()
    out = agent.audit_create2_salt(_mod.Create2SaltCollisionInput(**data))
    return out.model_dump()


# Clean / passing: salt incorporates msg.sender via keccak256.
_SECURE = "\n".join(
    [
        "contract Factory {",
        "    function deploy(bytes32 s) public {",
        "        bytes32 realSalt = keccak256(abi.encodePacked(msg.sender, s));",
        "        new Wallet{salt: realSalt}();",
        "    }",
        "}",
    ]
)

# Vulnerable path 1: `new C{salt: ...}` without msg.sender.
_NEW_SALT_VULN = "\n".join(
    [
        "contract Factory {",
        "    function deploy(bytes32 salt) public {",
        "        new Wallet{salt: salt}();",
        "    }",
        "}",
    ]
)

# Vulnerable path 2: Yul create2 without msg.sender.
_YUL_VULN = "\n".join(
    [
        "contract Factory {",
        "    function yulDeploy(bytes32 salt) public {",
        "        assembly {",
        "            let addr := create2(0, 0, 0x20, salt)",
        "        }",
        "    }",
        "}",
    ]
)

# Yul create2 BUT with msg.sender referenced in body -> secure.
_YUL_SECURE = "\n".join(
    [
        "contract Factory {",
        "    function yulDeploy(bytes32 s) public {",
        "        bytes32 salt = keccak256(abi.encodePacked(msg.sender, s));",
        "        assembly {",
        "            let addr := create2(0, 0, 0x20, salt)",
        "        }",
        "    }",
        "}",
    ]
)

# Multiple functions: one safe, two distinct vulnerable kinds.
_MULTI = "\n".join(
    [
        "contract Factory {",
        "    function safe(bytes32 s) public {",
        "        bytes32 r = keccak256(abi.encodePacked(msg.sender, s));",
        "        new A{salt: r}();",
        "    }",
        "    function unsafeNew(bytes32 salt) external {",
        "        new B{salt: salt}();",
        "    }",
        "    function unsafeYul(bytes32 salt) external {",
        "        assembly { let a := create2(0, 0, 0x40, salt) }",
        "    }",
        "    function noDeploy() public { return; }",
        "}",
    ]
)

# Function whose args span multiple lines -> the header regex fails to match it
# (`.` does not cross newlines), so it is NOT scanned. Exercises that edge.
_MULTILINE_ARGS = "\n".join(
    [
        "contract Factory {",
        "    function deploy(",
        "        bytes32 salt",
        "    ) public {",
        "        new Wallet{salt: salt}();",
        "    }",
        "}",
    ]
)

# No functions / no CREATE2 at all.
_NO_FUNC = "contract Empty { uint256 public x = 1; }"

SAMPLES = [
    {"input": {"file_path": "Factory.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "Factory.sol", "solidity_code": _NEW_SALT_VULN}},
    {"input": {"file_path": "Factory.sol", "solidity_code": _YUL_VULN}},
    {"input": {"file_path": "Factory.sol", "solidity_code": _YUL_SECURE}},
    {"input": {"file_path": "Factory.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Factory.sol", "solidity_code": _MULTILINE_ARGS}},
    {"input": {"file_path": "Factory.sol", "solidity_code": _NO_FUNC}},
    {"input": {"file_path": "Factory.sol", "solidity_code": ""}},
    {"input": {"file_path": "Factory.sol", "solidity_code": _NEW_SALT_VULN, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Factory.sol", "solidity_code": _NEW_SALT_VULN},
     "env": {"PI_CREATE2_SALT_STRICT_MODE": "false"}},
    {"input": {"file_path": "Factory.sol", "solidity_code": _YUL_VULN},
     "env": {"PI_CREATE2_SALT_STRICT_MODE": "true"}},
]
