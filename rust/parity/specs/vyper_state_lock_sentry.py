"""Parity spec for PiVyperStateLockSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiVyperStateLockSentry"

_mod = load_py_agent("pi_vyper_state_lock_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiVyperStateLockSentry()
    out = agent.audit_vyper_lock(_mod.VyperLockInput(**data))
    return out.model_dump()


# Secure: external call + state mod BUT guarded by @nonreentrant -> not flagged.
_SECURE = "\n".join(
    [
        "@external",
        "@nonreentrant('lock')",
        "def withdraw(amount: uint256):",
        "    self.balance -= amount",
        '    raw_call(msg.sender, b"")',
    ]
)

# Vulnerable via raw_call + state assignment, no nonreentrant decorator.
_VULN_RAWCALL = "\n".join(
    [
        "@external",
        "def withdraw():",
        '    raw_call(msg.sender, b"")',
        "    self.balance = 0",
    ]
)

# Vulnerable via method-style external call (erc20.transfer) + augmented assign.
_VULN_METHODCALL = "\n".join(
    [
        "@external",
        "def transfer(to: address, amt: uint256):",
        "    self.balance += amt",
        "    erc20.transfer(to, amt)",
    ]
)

# Vulnerable via ext_call keyword + state mod.
_VULN_EXTCALL = "\n".join(
    [
        "@external",
        "def claim():",
        "    self.total -= 1",
        "    ext_call(target)",
    ]
)

# External call but NO state modification -> safe (not flagged).
_EXT_NO_STATEMOD = "\n".join(
    [
        "@external",
        "def f():",
        '    raw_call(p, q)',
    ]
)

# State modification but NO external call -> safe (not flagged).
_STATEMOD_NO_EXT = "\n".join(
    [
        "@external",
        "def setter():",
        "    self.balance = 5",
    ]
)

# Multiple functions: one safe (guarded), one vulnerable.
_MULTI = "\n".join(
    [
        "@external",
        "@nonreentrant('lock')",
        "def safe_fn(amount: uint256):",
        "    self.bal -= amount",
        '    raw_call(msg.sender, b"")',
        "",
        "@external",
        "def bad_fn(amount: uint256):",
        "    self.bal += amount",
        "    erc20.transfer(target, amount)",
    ]
)

# No function definitions at all.
_NO_FUNCS = "x: uint256\nself.foo = 1\n"

SAMPLES = [
    {"input": {"file_path": "a.vy", "vyper_code": _SECURE}},
    {"input": {"file_path": "a.vy", "vyper_code": _VULN_RAWCALL}},
    {"input": {"file_path": "a.vy", "vyper_code": _VULN_METHODCALL}},
    {"input": {"file_path": "a.vy", "vyper_code": _VULN_EXTCALL}},
    {"input": {"file_path": "a.vy", "vyper_code": _EXT_NO_STATEMOD}},
    {"input": {"file_path": "a.vy", "vyper_code": _STATEMOD_NO_EXT}},
    {"input": {"file_path": "a.vy", "vyper_code": _MULTI}},
    {"input": {"file_path": "a.vy", "vyper_code": _NO_FUNCS}},
    {"input": {"file_path": "a.vy", "vyper_code": ""}},
    {"input": {"file_path": "a.vy", "vyper_code": _VULN_RAWCALL, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "a.vy", "vyper_code": _VULN_RAWCALL},
     "env": {"PI_VYPER_LOCK_STRICT_MODE": "false"}},
    # strict env explicitly true -> REJECTED
    {"input": {"file_path": "a.vy", "vyper_code": _VULN_RAWCALL},
     "env": {"PI_VYPER_LOCK_STRICT_MODE": "true"}},
]
