"""Parity spec for PiBackupIntegrityChecker.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiBackupIntegrityChecker"

_mod = load_py_agent("pi_backup_integrity_checker.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiBackupIntegrityChecker()
    out = agent.check_backup(_mod.BackupInput(**data))
    return out.model_dump()


_CLEAN = "encryption: true\nreplication: true\nretention: 30d"
_UNENCRYPTED = "encryption: false\nreplication: true\nretention: 30d"
_UNENCRYPTED_WORD = "Backups are UNENCRYPTED in the staging vault."
_NO_REPLICATION = "encryption: true\nreplication: disabled\nretention: 30d"
_REPLICATE_FALSE = "encryption: true\nreplicate=false\nretention: 30d"
_SHORT_RETENTION = "encryption: true\nreplication: true\nretention: 1d"
# Mixed case input exercises the .lower() normalisation path.
_MIXED_CASE = "Encryption: FALSE\nReplication: DISABLED\nRetention: 0"

SAMPLES = [
    # Clean / passing config.
    {"input": {"backup_config": _CLEAN}},
    # Unencrypted -> risk 85 -> FAILED_COMPLIANCE under strict default.
    {"input": {"backup_config": _UNENCRYPTED}},
    # "unencrypted" keyword path.
    {"input": {"backup_config": _UNENCRYPTED_WORD}},
    # Single point of failure (replication disabled) -> risk 70.
    {"input": {"backup_config": _NO_REPLICATION}},
    # replicate=false variant -> risk 70.
    {"input": {"backup_config": _REPLICATE_FALSE}},
    # Short retention path -> risk 60.
    {"input": {"backup_config": _SHORT_RETENTION}},
    # All three issues + mixed case -> highest risk wins (85).
    {"input": {"backup_config": _MIXED_CASE}},
    # Empty config -> nothing flagged, PASSED.
    {"input": {"backup_config": ""}},
    # Non-strict env -> risk > 30 but is_secure stays True -> WARN_COMPLIANCE.
    {"input": {"backup_config": _UNENCRYPTED},
     "env": {"PI_BACKUP_STRICT_MODE": "false"}},
    # Strict env explicitly true -> FAILED_COMPLIANCE.
    {"input": {"backup_config": _UNENCRYPTED},
     "env": {"PI_BACKUP_STRICT_MODE": "true"}},
]
