"""Parity spec for PiEncryptionComplianceChecker.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiEncryptionComplianceChecker"

_mod = load_py_agent("pi_encryption_compliance_checker.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiEncryptionComplianceChecker()
    out = agent.check_encryption_compliance(_mod.EncryptionInput(**data))
    return out.model_dump()


_CLEAN = "encryption: AES-256-GCM enabled; tls 1.3 only"
_WEAK = "cipher_suite = 3DES-CBC, fallback = RC4-MD5"
_LEGACY_TLS = "protocol = SSLv3; allow tlsv1.0 = true"
_DISABLED = "storage:\n  encryption: false\n  mode: unencrypted"
_MULTI = "cipher = DES; protocol = ssl; encryption: disabled"

SAMPLES = [
    # clean / passing config -> PASSED, risk 0
    {"input": {"resource_type": "database", "config_snippet": _CLEAN}},
    # weak crypto algorithm path (risk 90)
    {"input": {"resource_type": "connection", "config_snippet": _WEAK}},
    # legacy TLS/SSL protocol path (risk 80)
    {"input": {"resource_type": "endpoint", "config_snippet": _LEGACY_TLS}},
    # disabled encryption path (risk 85)
    {"input": {"resource_type": "bucket", "config_snippet": _DISABLED}},
    # all three gaps at once -> risk capped at max (90)
    {"input": {"resource_type": "service", "config_snippet": _MULTI}},
    # empty / edge config -> no gaps, PASSED
    {"input": {"resource_type": "bucket", "config_snippet": ""}},
    # non-strict env -> WARN path, is_secure stays True despite risk > 30
    {"input": {"resource_type": "connection", "config_snippet": _WEAK},
     "env": {"PI_ENCRYPTION_STRICT_MODE": "false"}},
    # strict env explicitly true -> FAILED path
    {"input": {"resource_type": "connection", "config_snippet": _WEAK},
     "env": {"PI_ENCRYPTION_STRICT_MODE": "true"}},
]
