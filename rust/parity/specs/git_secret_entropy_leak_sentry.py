"""Parity spec for PiGitSecretEntropyLeakSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}

NOTE: the Python agent exposes `calculate_shannon_entropy(data: str) -> float`
(a helper) and `audit_entropy_leaks(envelope) -> GitSecretEntropyLeakOutput`
(the public entry point that consumes the Input model and returns the Output
model). The parity surface is the Output model, so `run_python` calls
`audit_entropy_leaks`.
"""
from _util import load_py_agent

RUST_NAME = "PiGitSecretEntropyLeakSentry"

_mod = load_py_agent("pi_git_secret_entropy_leak_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiGitSecretEntropyLeakSentry()
    out = agent.audit_entropy_leaks(_mod.GitSecretEntropyLeakInput(**data))
    return out.model_dump()


# Clean: no quoted strings >=16 chars at all.
_CLEAN = "def greet():\n    return 'hi there'\n"

# High-entropy secret: random-looking 24-char token in single quotes.
_SECRET = "API_KEY = 'aZ9kQ2mB7xR4tL1pW8vN3cE6'"

# High-entropy secret in double quotes, multiple findings.
_MULTI = "\n".join(
    [
        "TOKEN = \"qW8eR2tY6uI0oP4aS7dF1gH3\"",
        "SECRET = 'zX1cV5bN9mK3jH7gF2dS4aQ8'",
        "comment = 'short'",
    ]
)

# Long quoted string but on the IGNORED list (contains 'http') -> skipped.
_IGNORED = "url = 'http_aZ9kQ2mB7xR4tL1pW8vN3cE6'"

# Long quoted string with LOW entropy (very repetitive) -> not flagged.
_LOW_ENTROPY = "pad = 'aaaaaaaaaaaaaaaaaaaaaaaa'"

# Quoted string of exactly 15 chars (below the 16-char minimum) -> no match.
_TOO_SHORT = "k = 'aZ9kQ2mB7xR4tL1'"

SAMPLES = [
    # clean / passing
    {"input": {"file_path": "a.py", "code_content": _CLEAN}},
    # single high-entropy secret -> REJECTED (strict default)
    {"input": {"file_path": "a.py", "code_content": _SECRET}},
    # multiple high-entropy secrets
    {"input": {"file_path": "a.py", "code_content": _MULTI}},
    # ignored keyword path (http) -> skipped, PASSED
    {"input": {"file_path": "a.py", "code_content": _IGNORED}},
    # low-entropy long string -> not flagged
    {"input": {"file_path": "a.py", "code_content": _LOW_ENTROPY}},
    # below 16-char minimum -> no match
    {"input": {"file_path": "a.py", "code_content": _TOO_SHORT}},
    # empty / edge input
    {"input": {"file_path": "a.py", "code_content": ""}},
    # custom check_level field still accepted
    {"input": {"file_path": "a.py", "code_content": _SECRET, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "a.py", "code_content": _SECRET},
     "env": {"PI_GIT_SECRET_ENTROPY_LEAK_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED
    {"input": {"file_path": "a.py", "code_content": _SECRET},
     "env": {"PI_GIT_SECRET_ENTROPY_LEAK_STRICT_MODE": "true"}},
]
