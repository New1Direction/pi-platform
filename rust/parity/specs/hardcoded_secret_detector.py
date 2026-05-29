"""Parity spec for PiHardcodedSecretDetector.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiHardcodedSecretDetector"

_mod = load_py_agent("pi_hardcoded_secret_detector.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiHardcodedSecretDetector()
    out = agent.scan_hardcoded_secrets(_mod.HardcodedSecretInput(**data))
    return out.model_dump()


_CLEAN = "def add(a, b):\n    return a + b\n"
_PRIVATE_KEY = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAUEw...\n"
    "-----END PRIVATE KEY-----\n"
)
_RSA_PRIVATE_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIICXAIBAAKBgQDabc...\n"
    "-----END RSA PRIVATE KEY-----\n"
)
_AWS_KEY = "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n"
_REAL_CRED = 'api_key = "sk-live-9f8a7b6c5d4e3f2g1h"\n'
_PLACEHOLDER_CRED = 'password = "your_password_here"\n'
_PLACEHOLDER_123 = 'token = "changeme123456"\n'
# Private key (50) + real credential (35) -> 85 -> FLAGGED, multiple findings
_COMBINED = (
    "-----BEGIN PRIVATE KEY-----\n"
    "secretmaterial...\n"
    "-----END PRIVATE KEY-----\n"
    'client_secret = "abcDEF1234ghiJKLmno"\n'
)
# AWS key (45) + private key (50) capped logic; >100 -> capped at 100
_ALL_PATHS = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "AKIAIOSFODNN7EXAMPLE\n"
    "-----END RSA PRIVATE KEY-----\n"
    'apikey = "ZmFrZS1zZWNyZXQtdmFsdWU"\n'
)

SAMPLES = [
    # clean / passing
    {"input": {"file_path": "clean.py", "file_content": _CLEAN}},
    # PEM private key block path (50.0 -> FLAGGED)
    {"input": {"file_path": "id.pem", "file_content": _PRIVATE_KEY}},
    # RSA private key path
    {"input": {"file_path": "id_rsa", "file_content": _RSA_PRIVATE_KEY}},
    # AWS access key path (45.0 -> FLAGGED)
    {"input": {"file_path": "aws.tf", "file_content": _AWS_KEY}},
    # real generic credential assignment path (35.0 -> FLAGGED)
    {"input": {"file_path": "config.py", "file_content": _REAL_CRED}},
    # placeholder credential -> skipped, stays secure
    {"input": {"file_path": "config.py", "file_content": _PLACEHOLDER_CRED}},
    # placeholder "123" credential -> skipped, stays secure
    {"input": {"file_path": "config.py", "file_content": _PLACEHOLDER_123}},
    # multiple findings combined
    {"input": {"file_path": "leak.py", "file_content": _COMBINED}},
    # several paths together (risk capped at 100.0)
    {"input": {"file_path": "leak.py", "file_content": _ALL_PATHS}},
    # empty / edge input
    {"input": {"file_path": "empty.txt", "file_content": ""}},
]
