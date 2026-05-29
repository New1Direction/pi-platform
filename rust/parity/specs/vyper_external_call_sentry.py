"""Parity spec for PiVyperExternalCallSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiVyperExternalCallSentry"

_mod = load_py_agent("pi_vyper_external_call_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiVyperExternalCallSentry()
    out = agent.audit_vyper_external_call(_mod.VyperExternalCallInput(**data))
    return out.model_dump()


# Clean: external call AFTER state change (Checks-Effects-Interactions respected)
_SECURE = "\n".join(
    [
        "@external",
        "def withdraw(amount: uint256):",
        "    self.balance -= amount",
        "    raw_call(msg.sender, b'')",
    ]
)

# Vulnerable via raw_call then `self.x = ...`
_REENTRANT_ASSIGN = "\n".join(
    [
        "@external",
        "def withdraw(amount: uint256):",
        "    raw_call(msg.sender, b'')",
        "    self.balance = 0",
    ]
)

# Vulnerable via ext_call then augmented assignment `+=`
_REENTRANT_AUGMENTED = "\n".join(
    [
        "@nonreentrant('lock')",
        "@external",
        "def claim():",
        "    ext_call(self.target)",
        "    self.total += 1",
    ]
)

# Comment lines must be ignored; here the only state mod is in a comment so SECURE
_COMMENTS_IGNORED = "\n".join(
    [
        "@external",
        "def safe():",
        "    raw_call(msg.sender, b'')",
        "    # self.balance = 0  (this is just a comment)",
        "    return True",
    ]
)

# Multiple functions, one secure + one vulnerable
_MIXED = "\n".join(
    [
        "@view",
        "def get_balance() -> uint256:",
        "    return self.balance",
        "",
        "@external",
        "def drain():",
        "    raw_call(attacker, b'')",
        "    self.balance = 0",
    ]
)

# No external call at all -> secure regardless of state writes
_NO_EXT_CALL = "\n".join(
    [
        "@external",
        "def setup():",
        "    self.owner = msg.sender",
        "    self.total = 100",
    ]
)

# No function definitions at all
_NO_FUNCS = "# just a module-level comment\nWAD: constant(uint256) = 10 ** 18"

SAMPLES = [
    {"input": {"file_path": "vault.vy", "vyper_code": _SECURE}},
    {"input": {"file_path": "vault.vy", "vyper_code": _REENTRANT_ASSIGN}},
    {"input": {"file_path": "vault.vy", "vyper_code": _REENTRANT_AUGMENTED}},
    {"input": {"file_path": "vault.vy", "vyper_code": _COMMENTS_IGNORED}},
    {"input": {"file_path": "vault.vy", "vyper_code": _MIXED}},
    {"input": {"file_path": "vault.vy", "vyper_code": _NO_EXT_CALL}},
    {"input": {"file_path": "vault.vy", "vyper_code": _NO_FUNCS}},
    {"input": {"file_path": "vault.vy", "vyper_code": ""}},
    {"input": {"file_path": "vault.vy", "vyper_code": _REENTRANT_ASSIGN, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "vault.vy", "vyper_code": _REENTRANT_ASSIGN},
     "env": {"PI_VYPER_EXTERNAL_CALL_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "vault.vy", "vyper_code": _REENTRANT_AUGMENTED},
     "env": {"PI_VYPER_EXTERNAL_CALL_STRICT_MODE": "true"}},
]
