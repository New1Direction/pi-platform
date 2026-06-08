from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class LogLeakInput(BaseModel):
    log_file_path: str = Field(..., description="Path to the log file being analyzed")
    log_content: str = Field(..., description="Raw text line or block content from logs")


class LogLeakOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no sensitive keys/credentials leak inside logs")
    flagged_leaks: List[str] = Field(default_factory=list, description="List of detected credential exposures")
    risk_score: float = Field(..., description="Severity risk rating from 0.0 to 100.0")
    status: str = Field(..., description="Audit security status classification")


class PiSensitiveLogLeakSentry:
    """Specialized log scanner searching for exposed keys, passwords, and tokens inside system logs."""

    def __init__(self) -> None:
        self.agent_name = "PiSensitiveLogLeakSentry"

    def audit_log_leaks(self, input_envelope: LogLeakInput) -> LogLeakOutput:
        content = input_envelope.log_content
        findings = []
        risk_score = 0.0

        # Scan for password leaks
        if "password" in content.lower():
            findings.append("password leak")
            risk_score += 40.0

        # Scan for secret key or token exposures
        if any(tok in content.lower() for tok in ["secret", "api_key", "token", "private_key"]):
            findings.append("token or secret exposure in log line")
            risk_score += 45.0

        # Scan for standard private key tags
        if "begin private key" in content.lower():
            findings.append("private key block leak")
            risk_score += 50.0

        risk_score = min(risk_score, 100.0)
        is_secure = risk_score < 40.0
        status = "FLAGGED" if not is_secure else "PASSED"

        return LogLeakOutput(is_secure=is_secure, flagged_leaks=findings, risk_score=risk_score, status=status)
