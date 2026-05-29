"""Parity spec for PiVyperStorageLayoutCollisionSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiVyperStorageLayoutCollisionSentry"

_mod = load_py_agent("pi_vyper_storage_layout_collision_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiVyperStorageLayoutCollisionSentry()
    out = agent.audit_vyper_storage_collision(_mod.VyperStorageCollisionInput(**data))
    return out.model_dump()


# Clean layout: no upgrade markers anywhere -> secure / PASSED.
_CLEAN = "\n".join(
    [
        "owner: public(address)",
        "balance: uint256",
        "total_supply: uint256",
    ]
)

# _v2 marker declared before an older (unmarked) variable -> collision.
_V2_OUT_OF_ORDER = "\n".join(
    [
        "owner: public(address)",
        "balance_v2: uint256",
        "total_supply: uint256",
    ]
)

# _upgrade marker declared before older vars -> collision.
_UPGRADE_OUT_OF_ORDER = "\n".join(
    [
        "admin_upgrade: address",
        "owner: public(address)",
        "balance: uint256",
    ]
)

# new_ marker declared before older vars -> collision.
_NEW_OUT_OF_ORDER = "\n".join(
    [
        "owner: public(address)",
        "new_feature_flag: bool",
        "legacy_value: uint256",
    ]
)

# Upgrade marker is LAST -> idx == len-1 -> NOT flagged (safe append).
_UPGRADE_AT_END = "\n".join(
    [
        "owner: public(address)",
        "total_supply: uint256",
        "balance_v2: uint256",
    ]
)

# constant / immutable types are skipped; the remaining _v2 is out of order.
_CONST_IMMUTABLE = "\n".join(
    [
        "MAX_SUPPLY: constant(uint256) = 10000",
        "DEPLOYER: immutable(address)",
        "counter_v2: uint256",
        "owner: public(address)",
    ]
)

# Functions / decorators / comments exercise the in_fn scope tracking.
# The state var after the function block (no leading indent, has ':') resets
# in_fn before being parsed; the _upgrade var precedes an older var -> flagged.
_WITH_FUNCTIONS = "\n".join(
    [
        "# top-level comment",
        "owner: public(address)",
        "@external",
        "def deposit(amount: uint256):",
        "    self.owner = msg.sender",
        "config_upgrade: uint256",
        "balance: uint256",
    ]
)

SAMPLES = [
    {"input": {"file_path": "clean.vy", "vyper_code": _CLEAN}},
    {"input": {"file_path": "v2.vy", "vyper_code": _V2_OUT_OF_ORDER}},
    {"input": {"file_path": "upgrade.vy", "vyper_code": _UPGRADE_OUT_OF_ORDER}},
    {"input": {"file_path": "new.vy", "vyper_code": _NEW_OUT_OF_ORDER}},
    {"input": {"file_path": "safe_end.vy", "vyper_code": _UPGRADE_AT_END}},
    {"input": {"file_path": "const.vy", "vyper_code": _CONST_IMMUTABLE}},
    {"input": {"file_path": "fns.vy", "vyper_code": _WITH_FUNCTIONS}},
    {"input": {"file_path": "empty.vy", "vyper_code": ""}},
    {"input": {"file_path": "v2.vy", "vyper_code": _V2_OUT_OF_ORDER, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "v2.vy", "vyper_code": _V2_OUT_OF_ORDER},
     "env": {"PI_VYPER_STORAGE_COLLISION_STRICT_MODE": "false"}},
    # strict env -> REJECTED path
    {"input": {"file_path": "v2.vy", "vyper_code": _V2_OUT_OF_ORDER},
     "env": {"PI_VYPER_STORAGE_COLLISION_STRICT_MODE": "true"}},
]
