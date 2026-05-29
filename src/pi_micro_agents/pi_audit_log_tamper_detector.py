from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_LOG_STRICT_MODE")


class LogInput(BaseModel):
    log_content: str = Field(..., description="Audit log entries, events, or metadata representation")


class LogOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if audit log sequences appear free of manipulation anomalies")
    anomalies: List[str] = Field(
        default_factory=list, description="List of detected audit log anomalies or gap warnings"
    )
    risk_score: float = Field(..., description="Audit risk evaluation score (0.0 to 100.0)")
    status: str = Field(..., description="Audit tamper status")


class PiAuditLogTamperDetector:
    """Scans system logs for sequence gaps, deletion queries, or audit record modifications by unauthorized actors."""

    def __init__(self) -> None:
        self.agent_name = "PiAuditLogTamperDetector"

    def detect_tampering(self, input_envelope: LogInput) -> LogOutput:
        content = input_envelope.log_content.lower()
        anomalies = []
        risk_score = 0.0

        # Gap sequences / Missing indices
        if "gap detected" in content or "missing log sequence" in content or "sequence mismatch" in content:
            anomalies.append("Audit Log Gap: System detected sequence ID discrepancies in consecutive events.")
            risk_score = max(risk_score, 80.0)

        # Clear or truncate log indicators
        if "rm -rf" in content or "clear logs" in content or "truncate table" in content or "log deleted" in content:
            anomalies.append("Destructive Action: Administrative system commands executed to clear or truncate logs.")
            risk_score = max(risk_score, 95.0)

        # Deletion by unauthorized user
        if "delete" in content and "anonymous" in content:
            anomalies.append("Unauthorized Log Deletion: Anonymous or guest role attempted delete/purge operations.")
            risk_score = max(risk_score, 90.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "ANOMALIES_DETECTED"
        if risk_score > 0.0 and is_sec:
            status = "WARN_ANOMALIES"

        return LogOutput(
            is_secure=is_sec,
            anomalies=anomalies,
            risk_score=risk_score,
            status=status,
        )
