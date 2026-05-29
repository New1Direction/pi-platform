"""Parity spec for PiSolidityUpgradeableInitializerSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityUpgradeableInitializerSentry"

_mod = load_py_agent("pi_solidity_upgradeable_initializer_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityUpgradeableInitializerSentry()
    out = agent.audit_upgradeable_initializer(_mod.UpgradeableInitInput(**data))
    return out.model_dump()


# Clean upgradeable contract: constructor disables initializers and the
# initialize() function is guarded by the `initializer` modifier.
_SECURE = "\n".join(
    [
        "import {Initializable} from '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol';",
        "contract Vault is Initializable {",
        "    uint256 public total;",
        "    constructor() {",
        "        _disableInitializers();",
        "    }",
        "    function initialize(uint256 amount) public initializer {",
        "        total = amount;",
        "    }",
        "}",
    ]
)

# Upgradeable, but constructor does NOT call _disableInitializers().
_BAD_CONSTRUCTOR = "\n".join(
    [
        "import {Initializable} from 'x';",
        "contract Vault is Initializable {",
        "    constructor() {",
        "        total = 0;",
        "    }",
        "    function initialize(uint256 amount) public initializer {",
        "        total = amount;",
        "    }",
        "}",
    ]
)

# Upgradeable (mentions `initializer` somewhere) but the initialize() function
# itself has no guard in its definition.
_UNGUARDED_INIT = "\n".join(
    [
        "// uses initializer pattern",
        "contract Vault {",
        "    function initialize(uint256 amount) public {",
        "        total = amount;",
        "    }",
        "}",
    ]
)

# Both problems: missing _disableInitializers AND an unguarded reinitialize fn.
_BOTH = "\n".join(
    [
        "import {Initializable} from 'x';",
        "contract Vault is Initializable {",
        "    constructor() {",
        "        owner = msg.sender;",
        "    }",
        "    function initializeVault(uint256 amount) public {",
        "        total = amount;",
        "    }",
        "}",
    ]
)

# onlyInitializing-guarded function (the other accepted guard keyword).
_ONLY_INITIALIZING = "\n".join(
    [
        "contract Vault {",
        "    function initialize(uint256 amount) public onlyInitializing {",
        "        total = amount;",
        "    }",
        "}",
    ]
)

# Not upgradeable at all -> nothing scanned, always secure.
_NON_UPGRADEABLE = "\n".join(
    [
        "contract Plain {",
        "    function transfer(address to, uint256 v) public {",
        "        balances[to] += v;",
        "    }",
        "}",
    ]
)


SAMPLES = [
    # clean / passing upgradeable contract
    {"input": {"file_path": "Vault.sol", "solidity_code": _SECURE},
     "env": {"PI_UPGRADE_INIT_STRICT_MODE": "true"}},
    # constructor missing _disableInitializers -> REJECTED
    {"input": {"file_path": "Vault.sol", "solidity_code": _BAD_CONSTRUCTOR},
     "env": {"PI_UPGRADE_INIT_STRICT_MODE": "true"}},
    # unguarded initialize function -> REJECTED
    {"input": {"file_path": "Vault.sol", "solidity_code": _UNGUARDED_INIT},
     "env": {"PI_UPGRADE_INIT_STRICT_MODE": "true"}},
    # both findings -> REJECTED, two vulnerable functions
    {"input": {"file_path": "Vault.sol", "solidity_code": _BOTH},
     "env": {"PI_UPGRADE_INIT_STRICT_MODE": "true"}},
    # onlyInitializing guard accepted -> PASSED
    {"input": {"file_path": "Vault.sol", "solidity_code": _ONLY_INITIALIZING},
     "env": {"PI_UPGRADE_INIT_STRICT_MODE": "true"}},
    # non-upgradeable contract -> PASSED, nothing scanned
    {"input": {"file_path": "Plain.sol", "solidity_code": _NON_UPGRADEABLE},
     "env": {"PI_UPGRADE_INIT_STRICT_MODE": "true"}},
    # empty / edge input -> PASSED
    {"input": {"file_path": "Empty.sol", "solidity_code": ""},
     "env": {"PI_UPGRADE_INIT_STRICT_MODE": "true"}},
    # custom check_level still honored by the model
    {"input": {"file_path": "Vault.sol", "solidity_code": _BAD_CONSTRUCTOR,
               "check_level": "MEDIUM"},
     "env": {"PI_UPGRADE_INIT_STRICT_MODE": "true"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Vault.sol", "solidity_code": _BAD_CONSTRUCTOR},
     "env": {"PI_UPGRADE_INIT_STRICT_MODE": "false"}},
    # strict env explicit -> REJECTED path
    {"input": {"file_path": "Vault.sol", "solidity_code": _UNGUARDED_INIT},
     "env": {"PI_UPGRADE_INIT_STRICT_MODE": "true"}},
]
