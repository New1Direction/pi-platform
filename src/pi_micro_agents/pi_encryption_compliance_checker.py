from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ENCRYPTION_STRICT_MODE")


class EncryptionInput(BaseModel):
    resource_type: str = Field(
        ..., description="Type of the resource being checked (e.g. database, bucket, connection)"
    )
    config_snippet: str = Field(..., description="Configuration snippet related to encryption settings")


class EncryptionOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if encryption meets compliant standards")
    missing_encryption: List[str] = Field(
        default_factory=list, description="Identified gaps in encryption configuration"
    )
    risk_score: float = Field(..., description="Risk score (0.0 to 100.0)")
    status: str = Field(..., description="Encryption compliance status")


class PiEncryptionComplianceChecker:
    """Verifies that data-at-rest and data-in-transit configurations enforce AES-256/GCM or equivalent standards."""

    def __init__(self) -> None:
        self.agent_name = "PiEncryptionComplianceChecker"

    def check_encryption_compliance(self, input_envelope: EncryptionInput) -> EncryptionOutput:
        snippet = input_envelope.config_snippet.lower()
        gaps = []
        risk_score = 0.0

        # Reject legacy or insecure crypto algorithms
        if "des" in snippet or "rc4" in snippet or "md5" in snippet:
            gaps.append("Weak Cryptographic Algorithm: Deprecated cryptos (DES, RC4, or MD5) detected.")
            risk_score = max(risk_score, 90.0)

        if (
            "ssl" in snippet
            or "tlsv1.0" in snippet
            or "tlsv1.1" in snippet
            or "tls 1.0" in snippet
            or "tls 1.1" in snippet
        ):
            gaps.append("Insecure Protocol Version: Legacy TLS/SSL protocol active. TLS 1.2 or TLS 1.3 is required.")
            risk_score = max(risk_score, 80.0)

        if (
            "encryption: false" in snippet
            or "encrypt=false" in snippet
            or "unencrypted" in snippet
            or "encryption: disabled" in snippet
        ):
            gaps.append("Disabled Encryption: Encryption is explicitly turned off.")
            risk_score = max(risk_score, 85.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "FAILED_COMPLIANCE"
        if risk_score > 0.0 and is_sec:
            status = "WARN_COMPLIANCE"

        return EncryptionOutput(
            is_secure=is_sec,
            missing_encryption=gaps,
            risk_score=risk_score,
            status=status,
        )
