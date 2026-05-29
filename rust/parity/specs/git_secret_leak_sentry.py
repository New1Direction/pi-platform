"""Parity spec for PiGitSecretLeakSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiGitSecretLeakSentry"

_mod = load_py_agent("pi_git_secret_leak_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiGitSecretLeakSentry()
    out = agent.audit_secrets(_mod.GitSecretLeakInput(**data))
    return out.model_dump()


_CLEAN = "def add(a, b):\n    return a + b\n"
_RSA = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA1234567890\n"
    "-----END RSA PRIVATE KEY-----\n"
)
_GENERIC_KEY = (
    "-----BEGIN PRIVATE KEY-----\nMIIabcdefg\n-----END PRIVATE KEY-----\n"
)
_STRIPE = 'stripe_key = "STRIPE_LIVE_KEY_SCRUBBED"'
_AWS_MWS = "token = amzn.mws.4ea38b7b-f563-7709-4bae-87aea1234567"
_GOOGLE = "api = 'GOOGLE_API_KEY_SCRUBBEDw'"
_AWS_SECRET = (
    'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
)
# 12 plain English words, no secret context -> NOT flagged as mnemonic.
_MNEMONIC_PLAIN = "the quick brown fox jumps over the lazy dog and then runs"
# 12 words WITH secret context -> flagged as mnemonic.
_MNEMONIC_CTX = (
    "seed phrase: the quick brown fox jumps over the lazy dog and then runs"
)

SAMPLES = [
    # clean / passing
    {"input": {"file_path": "ok.py", "file_content": _CLEAN}},
    # each distinct flagged path
    {"input": {"file_path": "k.pem", "file_content": _RSA}},
    {"input": {"file_path": "k.pem", "file_content": _GENERIC_KEY}},
    {"input": {"file_path": "s.py", "file_content": _STRIPE}},
    {"input": {"file_path": "a.py", "file_content": _AWS_MWS}},
    {"input": {"file_path": "g.py", "file_content": _GOOGLE}},
    {"input": {"file_path": "c.py", "file_content": _AWS_SECRET}},
    # mnemonic heuristic both branches
    {"input": {"file_path": "m.txt", "file_content": _MNEMONIC_PLAIN}},
    {"input": {"file_path": "m.txt", "file_content": _MNEMONIC_CTX}},
    # empty / edge
    {"input": {"file_path": "empty.py", "file_content": ""}},
    # env branches: strict vs non-strict WARN path
    {"input": {"file_path": "k.pem", "file_content": _RSA},
     "env": {"PI_GIT_SECRET_STRICT_MODE": "false"}},
    {"input": {"file_path": "k.pem", "file_content": _RSA},
     "env": {"PI_GIT_SECRET_STRICT_MODE": "true"}},
]
