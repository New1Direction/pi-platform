"""Parity spec for PiCertificateRotationWatcher.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiCertificateRotationWatcher"

_mod = load_py_agent("pi_certificate_rotation_watcher.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiCertificateRotationWatcher()
    out = agent.watch_certificate(_mod.CertInput(**data))
    return out.model_dump()


_CLEAN = "Issued by GlobalTrust CA, RSA-2048, expires in 365 days, auto-rotation enabled"
_SELF_SIGNED = "This is a SELF-Signed certificate generated locally for testing"
_SELFSIGNED_NODASH = "issuer=selfsigned-root; subject=selfsigned-root"
_EXPIRING_FLAG = "status: active, expiring: true, valid CA chain present"
_EXPIRES_5 = "Certificate from real CA but expires in 5 days, please renew"
_EXPIRES_SOON = "real CA anchored, marked expires_soon by monitor"
_WEAK_DASH = "Real CA, key: RSA-1024, expires in 200 days"
_WEAK_SIZE = "Real CA chain, key_size: 1024, long lifetime"
_ALL = "self-signed root, expiring: true, key_size: 1024"

SAMPLES = [
    # clean / passing input
    {"input": {"cert_content": _CLEAN}},
    # self-signed (hyphenated) vulnerable path
    {"input": {"cert_content": _SELF_SIGNED}},
    # self-signed (no dash) vulnerable path
    {"input": {"cert_content": _SELFSIGNED_NODASH}},
    # expiring via "expiring: true"
    {"input": {"cert_content": _EXPIRING_FLAG}},
    # expiring via "expires in 5 days"
    {"input": {"cert_content": _EXPIRES_5}},
    # expiring via "expires_soon"
    {"input": {"cert_content": _EXPIRES_SOON}},
    # weak key via "rsa-1024"
    {"input": {"cert_content": _WEAK_DASH}},
    # weak key via "key_size: 1024"
    {"input": {"cert_content": _WEAK_SIZE}},
    # all three issues combined (risk_score should be max == 90.0)
    {"input": {"cert_content": _ALL}},
    # empty / edge input
    {"input": {"cert_content": ""}},
    # env: non-strict -> flagged cert is coerced to is_secure True, WARN path
    {"input": {"cert_content": _SELF_SIGNED},
     "env": {"PI_CERT_STRICT_MODE": "false"}},
    # env: strict explicitly -> FAILED_COMPLIANCE
    {"input": {"cert_content": _SELF_SIGNED},
     "env": {"PI_CERT_STRICT_MODE": "true"}},
]
