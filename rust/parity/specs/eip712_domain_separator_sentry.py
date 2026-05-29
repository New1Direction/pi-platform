"""Parity spec for PiEIP712DomainSeparatorSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiEIP712DomainSeparatorSentry"

_mod = load_py_agent("pi_eip712_domain_separator_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiEIP712DomainSeparatorSentry()
    out = agent.audit_domain_separator(_mod.DomainSeparatorInput(**data))
    return out.model_dump()


# --- Solidity fixtures ---

# Clean / passing: non-upgradeable contract with an immutable separator
# (only flagged when upgradeable).
_NON_UPGRADEABLE = "\n".join(
    [
        "contract Token {",
        "    bytes32 public immutable DOMAIN_SEPARATOR;",
        "    constructor() {",
        "        DOMAIN_SEPARATOR = keccak256('x');",
        "    }",
        "}",
    ]
)

# Upgradeable + immutable public DOMAIN_SEPARATOR -> vulnerable.
_UPGRADEABLE_IMMUTABLE = "\n".join(
    [
        "contract Token is Initializable {",
        "    bytes32 public immutable DOMAIN_SEPARATOR;",
        "    function init() public { /* ... */ }",
        "}",
    ]
)

# Upgradeable + constant public DOMAIN_SEPARATOR -> vulnerable.
_UPGRADEABLE_CONSTANT = "\n".join(
    [
        "contract Token is UUPSUpgradeable {",
        "    bytes32 public constant DOMAIN_SEPARATOR = 0x00;",
        "}",
    ]
)

# Upgradeable (via generic 'Upgradeable' marker) + bare immutable -> vulnerable.
_UPGRADEABLE_BARE_IMMUTABLE = "\n".join(
    [
        "contract Token is ERC20Upgradeable {",
        "    bytes32 immutable DOMAIN_SEPARATOR;",
        "}",
    ]
)

# Upgradeable + DOMAIN_SEPARATOR initialized inside the constructor -> vulnerable.
_UPGRADEABLE_CONSTRUCTOR_INIT = "\n".join(
    [
        "contract Token is Initializable {",
        "    bytes32 public DOMAIN_SEPARATOR;",
        "    constructor() {",
        "        DOMAIN_SEPARATOR = keccak256(abi.encode(block.chainid));",
        "    }",
        "}",
    ]
)

# Upgradeable but DOMAIN_SEPARATOR computed dynamically in an initializer ->
# secure (no immutable/constant, not in constructor body).
_UPGRADEABLE_DYNAMIC = "\n".join(
    [
        "contract Token is Initializable {",
        "    bytes32 public DOMAIN_SEPARATOR;",
        "    constructor() {}",
        "    function initialize() public initializer {",
        "        DOMAIN_SEPARATOR = keccak256(abi.encode(block.chainid));",
        "    }",
        "}",
    ]
)


SAMPLES = [
    # Clean: non-upgradeable, never flagged.
    {"input": {"file_path": "Token.sol", "solidity_code": _NON_UPGRADEABLE}},
    # Vulnerable path 1: upgradeable + public immutable.
    {"input": {"file_path": "Token.sol", "solidity_code": _UPGRADEABLE_IMMUTABLE}},
    # Vulnerable path 2: upgradeable + public constant.
    {"input": {"file_path": "Token.sol", "solidity_code": _UPGRADEABLE_CONSTANT}},
    # Vulnerable path 3: upgradeable + bare immutable.
    {"input": {"file_path": "Token.sol", "solidity_code": _UPGRADEABLE_BARE_IMMUTABLE}},
    # Vulnerable path 4: upgradeable + constructor init.
    {"input": {"file_path": "Token.sol", "solidity_code": _UPGRADEABLE_CONSTRUCTOR_INIT}},
    # Secure: upgradeable but dynamic separator in initializer.
    {"input": {"file_path": "Token.sol", "solidity_code": _UPGRADEABLE_DYNAMIC}},
    # Edge: empty source.
    {"input": {"file_path": "Token.sol", "solidity_code": ""}},
    # Non-default check_level still flags (check_level is unused by the agent).
    {"input": {"file_path": "Token.sol", "solidity_code": _UPGRADEABLE_IMMUTABLE, "check_level": "MEDIUM"}},
    # Non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "Token.sol", "solidity_code": _UPGRADEABLE_IMMUTABLE},
     "env": {"PI_DOMAIN_SEPARATOR_STRICT_MODE": "false"}},
    # Strict env -> REJECTED path.
    {"input": {"file_path": "Token.sol", "solidity_code": _UPGRADEABLE_IMMUTABLE},
     "env": {"PI_DOMAIN_SEPARATOR_STRICT_MODE": "true"}},
]
