"""Parity spec for PiAuditLogTamperDetector.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiAuditLogTamperDetector"

_mod = load_py_agent("pi_audit_log_tamper_detector.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiAuditLogTamperDetector()
    out = agent.detect_tampering(_mod.LogInput(**data))
    return out.model_dump()


_CLEAN = "INFO 2026-05-28 user alice logged in successfully; session opened"
_GAP = "WARN sequence mismatch between event 1042 and 1051 (Gap Detected)"
_DESTRUCTIVE = "root executed: rm -rf /var/log/audit && TRUNCATE TABLE audit_events"
_ANON_DELETE = "anonymous role attempted DELETE FROM audit_log WHERE 1=1"
_MULTI = "\n".join(
    [
        "missing log sequence id 7781",
        "operator ran clear logs command",
        "anonymous user issued delete request",
    ]
)

SAMPLES = [
    # clean / passing input -> PASSED, risk 0
    {"input": {"log_content": _CLEAN}},
    # gap path -> risk 80, strict -> ANOMALIES_DETECTED
    {"input": {"log_content": _GAP}},
    # destructive path -> risk 95
    {"input": {"log_content": _DESTRUCTIVE}},
    # unauthorized anonymous delete -> risk 90
    {"input": {"log_content": _ANON_DELETE}},
    # all three paths combined -> risk 95
    {"input": {"log_content": _MULTI}},
    # empty / edge input -> PASSED
    {"input": {"log_content": ""}},
    # non-strict env -> WARN_ANOMALIES, is_secure stays True even with anomalies
    {"input": {"log_content": _GAP},
     "env": {"PI_LOG_STRICT_MODE": "false"}},
    # explicit strict env -> ANOMALIES_DETECTED
    {"input": {"log_content": _GAP},
     "env": {"PI_LOG_STRICT_MODE": "true"}},
]
