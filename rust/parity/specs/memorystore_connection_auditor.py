"""Parity spec for PiMemorystoreConnectionAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiMemorystoreConnectionAuditor"

_mod = load_py_agent("pi_memorystore_connection_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiMemorystoreConnectionAuditor()
    out = agent.execute(_mod.MemorystoreConnectionInput(**data))
    return out.model_dump()


SAMPLES = [
    # Clean, fully-secure rediss connection in production -> PASS.
    {"input": {"connection_string": "rediss://cache.internal:6380",
               "require_tls": True, "deployment_env": "production"}},
    # Plain redis in production with require_tls -> TLS rule fires (FAIL path build-up).
    {"input": {"connection_string": "redis://cache.internal:6379",
               "require_tls": True, "deployment_env": "production"}},
    # Localhost/loopback host in production -> host rule fires.
    {"input": {"connection_string": "rediss://127.0.0.1:6380",
               "require_tls": True, "deployment_env": "production"}},
    # Embedded credentials (password only) -> creds rule fires.
    {"input": {"connection_string": "rediss://:s3cr3t@cache.internal:6380",
               "require_tls": True, "deployment_env": "production"}},
    # Embedded user+password + plain redis + localhost -> all three rules fire (FAIL, capped).
    {"input": {"connection_string": "redis://admin:pw@localhost:6379/0",
               "require_tls": True, "deployment_env": "production"}},
    # Invalid format -> early FAIL branch with risk 50.0.
    {"input": {"connection_string": "http://example.com:80",
               "require_tls": True, "deployment_env": "production"}},
    # Empty connection string -> invalid format branch.
    {"input": {"connection_string": ""}},
    # Plain redis but require_tls=False, default port path, uses defaults for env -> production host check still runs.
    {"input": {"connection_string": "redis://prod-cache.example.com",
               "require_tls": False, "deployment_env": "production"}},
    # Development env: TLS + host rules suppressed; default port 6380 for rediss.
    {"input": {"connection_string": "redis://localhost",
               "require_tls": True, "deployment_env": "development"}},
    # Staging env with mixed-case env name -> lower() normalization; creds only.
    {"input": {"connection_string": "redis://user:pass@staging-cache:6379",
               "require_tls": True, "deployment_env": "Staging"}},
    # Defaults exercised: only connection_string provided (require_tls=True, deployment_env="production").
    {"input": {"connection_string": "redis://0.0.0.0:6379"}},
]

# Regression coverage for the i64-overflow bug: Python int() is arbitrary
# precision so a 20+ digit port stays valid; the original Rust i64::parse
# overflowed and spuriously invalidated. These pin the fixed behavior.
SAMPLES += [
    {"input": {"connection_string": "rediss://cache.internal:99999999999999999999"}},      # 20 digits (overflows i64)
    {"input": {"connection_string": "redis://h:123456789012345678901234567890/0"}},        # 30 digits
    {"input": {"connection_string": "rediss://admin:pw@prod.example.com:18446744073709551616"}},  # 2^64
]
