"""Parity spec for PiVyperSecScanner.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiVyperSecScanner"

_mod = load_py_agent("pi_vyper_sec_scanner.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiVyperSecScanner()
    out = agent.audit_vyper(_mod.VyperScannerInput(**data))
    return out.model_dump()


# Clean, fully decorated contract on a non-vulnerable compiler -> PASSED.
_CLEAN = "\n".join(
    [
        "# @version 0.3.10",
        "",
        "@external",
        "def deposit():",
        "    pass",
        "",
        "@internal",
        "@view",
        "def balance() -> uint256:",
        "    return 0",
    ]
)

# Function with no decorator at all -> flagged (missing decorator path).
_MISSING_DECORATOR = "\n".join(
    [
        "# @version 0.3.10",
        "",
        "def orphan():",
        "    pass",
    ]
)

# Function preceded by an unrecognized decorator -> invalid-decorator path.
_INVALID_DECORATOR = "\n".join(
    [
        "# @version 0.3.10",
        "",
        "@bogus_decorator",
        "def weird():",
        "    pass",
    ]
)

# Vulnerable compiler version 0.3.7 + @nonreentrant -> global_compiler flag.
_VULN_COMPILER = "\n".join(
    [
        "# @version 0.3.7",
        "",
        "@external",
        "@nonreentrant('lock')",
        "def withdraw():",
        "    pass",
    ]
)

# Vulnerable 0.2.x compiler + @nonreentrant -> global_compiler flag.
_VULN_COMPILER_02 = "\n".join(
    [
        "# @version ^0.2.16",
        "",
        "@external",
        "@nonreentrant('x')",
        "def claim():",
        "    pass",
    ]
)

# Vulnerable compiler version but NO @nonreentrant -> compiler NOT flagged
# (only decorator audit runs); here everything is properly decorated -> PASSED.
_VULN_COMPILER_NO_LOCK = "\n".join(
    [
        "# @version 0.3.7",
        "",
        "@external",
        "def safe():",
        "    pass",
    ]
)

# Multiple findings: bad compiler + nonreentrant + an undecorated function.
_MULTI = "\n".join(
    [
        "# @version 0.3.4",
        "",
        "@external",
        "@nonreentrant('lock')",
        "def locked():",
        "    pass",
        "",
        "def undecorated():",
        "    pass",
    ]
)

SAMPLES = [
    {"input": {"file_path": "a.vy", "vyper_code": _CLEAN}},
    {"input": {"file_path": "a.vy", "vyper_code": _MISSING_DECORATOR}},
    {"input": {"file_path": "a.vy", "vyper_code": _INVALID_DECORATOR}},
    {"input": {"file_path": "a.vy", "vyper_code": _VULN_COMPILER}},
    {"input": {"file_path": "a.vy", "vyper_code": _VULN_COMPILER_02}},
    {"input": {"file_path": "a.vy", "vyper_code": _VULN_COMPILER_NO_LOCK}},
    {"input": {"file_path": "a.vy", "vyper_code": _MULTI}},
    # empty / edge input
    {"input": {"file_path": "a.vy", "vyper_code": ""}},
    {"input": {"file_path": "a.vy", "vyper_code": _INVALID_DECORATOR, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "a.vy", "vyper_code": _MISSING_DECORATOR},
     "env": {"PI_VYPER_STRICT_MODE": "false"}},
    {"input": {"file_path": "a.vy", "vyper_code": _MISSING_DECORATOR},
     "env": {"PI_VYPER_STRICT_MODE": "true"}},
]
