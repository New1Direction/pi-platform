"""Parity spec for PiAutomatedRotationEngine.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiAutomatedRotationEngine"

_mod = load_py_agent("pi_automated_rotation_engine.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiAutomatedRotationEngine()
    out = agent.rotate_credential(_mod.RotationInput(**data))
    return out.model_dump()


SAMPLES = [
    # typical AWS key rotation
    {"input": {"credential_type": "AWS_KEY", "target_identifier": "prod-access-key-1"}},
    # database password rotation
    {"input": {"credential_type": "DB_PASS", "target_identifier": "orders-db-master"}},
    # generic API key rotation
    {"input": {"credential_type": "API_KEY", "target_identifier": "billing-svc"}},
    # target identifier collides with the fixed "status" key -> overwrite path
    {"input": {"credential_type": "AWS_KEY", "target_identifier": "status"}},
    # target identifier collides with the fixed "version" key -> overwrite path
    {"input": {"credential_type": "DB_PASS", "target_identifier": "version"}},
    # target identifier collides with the fixed "target" key (self-overwrite)
    {"input": {"credential_type": "API_KEY", "target_identifier": "target"}},
    # empty-string edge inputs (still valid: both fields are required strings)
    {"input": {"credential_type": "", "target_identifier": ""}},
    # identifier with whitespace / unicode to stress key handling
    {"input": {"credential_type": "TLS_CERT", "target_identifier": "  edge node é  "}},
]
