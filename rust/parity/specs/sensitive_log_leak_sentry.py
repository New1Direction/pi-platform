"""Parity spec for PiSensitiveLogLeakSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiSensitiveLogLeakSentry"

_mod = load_py_agent("pi_sensitive_log_leak_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiSensitiveLogLeakSentry()
    out = agent.audit_log_leaks(_mod.LogLeakInput(**data))
    return out.model_dump()


SAMPLES = [
    # clean log, nothing flagged -> PASSED
    {"input": {"log_file_path": "app.log",
               "log_content": "INFO: request handled in 12ms"}},
    # password leak only -> risk 40.0, FLAGGED (40.0 not < 40.0)
    {"input": {"log_file_path": "app.log",
               "log_content": "user login PASSWORD=hunter2"}},
    # token/secret exposure path via 'secret'
    {"input": {"log_file_path": "auth.log",
               "log_content": "loaded client_secret from vault"}},
    # token/secret exposure path via 'api_key'
    {"input": {"log_file_path": "auth.log",
               "log_content": "header X-API_KEY=abc123"}},
    # token/secret exposure path via 'token'
    {"input": {"log_file_path": "auth.log",
               "log_content": "Bearer TOKEN issued for session"}},
    # token/secret exposure path via 'private_key'
    {"input": {"log_file_path": "auth.log",
               "log_content": "decrypting PRIVATE_KEY material"}},
    # private key block leak path
    {"input": {"log_file_path": "keys.log",
               "log_content": "-----BEGIN PRIVATE KEY-----\nMIIB...\n-----END PRIVATE KEY-----"}},
    # all three paths combined -> risk capped at 100.0
    {"input": {"log_file_path": "dump.log",
               "log_content": "password=p; api_key=k; -----BEGIN PRIVATE KEY-----"}},
    # empty content -> nothing flagged
    {"input": {"log_file_path": "empty.log", "log_content": ""}},
]
