"""Parity spec for PiMemoryZeroizeSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiMemoryZeroizeSentry"

_mod = load_py_agent("pi_memory_zeroize_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiMemoryZeroizeSentry()
    out = agent.audit_memory_zeroize(_mod.MemoryZeroizeInput(**data))
    return out.model_dump()


# Secure: uses an approved wipe token.
_SECURE = "void wipe() {\n    explicit_bzero(session_key, sizeof(session_key));\n}"

# Standard memset on a sensitive symbol -> DSE elidable finding.
_MEMSET = "void clear() {\n    memset(password, 0, sizeof(password));\n}"

# Sensitive symbol present but never wiped at all -> never-zeroized finding.
_NEVER = "void leak() {\n    char private_key[32];\n    use(private_key);\n}"

# Multiple memset calls on the same symbol -> one finding per match.
_MULTI_MEMSET = (
    "void clear() {\n"
    "    memset(secret, 0, sizeof(secret));\n"
    "    memset( secret , 0, 32);\n"
    "}"
)

# memset present AND a secure wipe present: still flags the memset (per-match),
# but the never-zeroized branch is suppressed.
_MIXED = (
    "void clear() {\n"
    "    memset(token, 0, sizeof(token));\n"
    "    SecureZeroMemory(token, sizeof(token));\n"
    "}"
)

# Two symbols: one securely wiped via Zeroize, one only memset.
_TWO_SYMBOLS = (
    "fn clear() {\n"
    "    cred.zeroize();\n"
    "    memset(buf, 0, len);\n"
    "}"
)

SAMPLES = [
    # Clean / passing input.
    {"input": {"file_path": "a.c", "source_code": _SECURE,
               "sensitive_symbols": ["session_key"]}},
    # memset DSE finding.
    {"input": {"file_path": "a.c", "source_code": _MEMSET,
               "sensitive_symbols": ["password"]}},
    # Never-zeroized finding.
    {"input": {"file_path": "a.c", "source_code": _NEVER,
               "sensitive_symbols": ["private_key"]}},
    # Multiple memset matches -> multiple findings.
    {"input": {"file_path": "a.c", "source_code": _MULTI_MEMSET,
               "sensitive_symbols": ["secret"]}},
    # memset + secure wipe both present.
    {"input": {"file_path": "a.c", "source_code": _MIXED,
               "sensitive_symbols": ["token"]}},
    # Two symbols with mixed handling. "Zeroize" token via .zeroize() does NOT
    # match (case-sensitive substring), so buf memset still flags and cred is
    # treated as never-zeroized unless a secure wipe token appears in code.
    {"input": {"file_path": "a.rs", "source_code": _TWO_SYMBOLS,
               "sensitive_symbols": ["cred", "buf"]}},
    # Symbol not present in code -> no findings.
    {"input": {"file_path": "a.c", "source_code": "int x = 1;",
               "sensitive_symbols": ["nonexistent"]}},
    # Empty / edge input.
    {"input": {"file_path": "a.c", "source_code": "",
               "sensitive_symbols": []}},
    # Non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "a.c", "source_code": _MEMSET,
               "sensitive_symbols": ["password"]},
     "env": {"PI_ZEROIZE_STRICT_MODE": "false"}},
    # Strict env explicitly true -> REJECTED path.
    {"input": {"file_path": "a.c", "source_code": _MEMSET,
               "sensitive_symbols": ["password"]},
     "env": {"PI_ZEROIZE_STRICT_MODE": "true"}},
]
