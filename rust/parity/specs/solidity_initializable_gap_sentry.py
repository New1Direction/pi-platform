"""Parity spec for PiSolidityInitializableGapSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSolidityInitializableGapSentry"

_mod = load_py_agent("pi_solidity_initializable_gap_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSolidityInitializableGapSentry()
    out = agent.audit_initializable_gap(_mod.InitializableGapInput(**data))
    return out.model_dump()


# Upgradeable contract WITH a proper storage gap -> secure / PASSED.
_SECURE = (
    "contract MyTokenUpgradeable is Initializable {\n"
    "    uint256 public total;\n"
    "    uint256[50] private __gap;\n"
    "}"
)

# Upgradeable-by-name, missing __gap -> flagged.
_MISSING_BY_NAME = (
    "contract VaultUpgradeable {\n"
    "    uint256 public balance;\n"
    "}"
)

# Upgradeable by inheriting Initializable, missing __gap -> flagged.
_MISSING_BY_INHERITANCE = (
    "contract Base is Initializable, OwnableUpgradeable {\n"
    "    address owner;\n"
    "}"
)

# `abstract` keyword present anywhere makes every contract count as upgradeable.
_ABSTRACT_TRIGGER = (
    "abstract contract Thing {\n"
    "    function foo() public virtual;\n"
    "}\n"
    "contract Plain {\n"
    "    uint256 x;\n"
    "}"
)

# Plain, non-upgradeable contract with no abstract keyword -> secure.
_PLAIN = (
    "contract PlainToken {\n"
    "    uint256 public supply;\n"
    "}"
)

# Multiple contracts: one upgradeable with gap (ok), one upgradeable missing gap (flagged).
_MULTI = (
    "contract AUpgradeable is Initializable {\n"
    "    uint256 a;\n"
    "    uint256[50] __gap;\n"
    "}\n"
    "contract BUpgradeable {\n"
    "    uint256 b;\n"
    "}"
)

# Gap declared with internal visibility and odd spacing -> still detected as secure.
_GAP_INTERNAL = (
    "contract WeirdUpgradeable is Initializable {\n"
    "    uint256 v;\n"
    "    uint256 [ 100 ] internal __gap ;\n"
    "}"
)

SAMPLES = [
    {"input": {"file_path": "Secure.sol", "solidity_code": _SECURE}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _MISSING_BY_NAME}},
    {"input": {"file_path": "Base.sol", "solidity_code": _MISSING_BY_INHERITANCE}},
    {"input": {"file_path": "Abstract.sol", "solidity_code": _ABSTRACT_TRIGGER}},
    {"input": {"file_path": "Plain.sol", "solidity_code": _PLAIN}},
    {"input": {"file_path": "Multi.sol", "solidity_code": _MULTI}},
    {"input": {"file_path": "Weird.sol", "solidity_code": _GAP_INTERNAL}},
    {"input": {"file_path": "Empty.sol", "solidity_code": ""}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _MISSING_BY_NAME, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "Vault.sol", "solidity_code": _MISSING_BY_NAME},
     "env": {"PI_INITIALIZABLE_GAP_STRICT_MODE": "false"}},
    {"input": {"file_path": "Vault.sol", "solidity_code": _MISSING_BY_NAME},
     "env": {"PI_INITIALIZABLE_GAP_STRICT_MODE": "true"}},
]
