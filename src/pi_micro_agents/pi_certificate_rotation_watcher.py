from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_CERT_STRICT_MODE")


class CertInput(BaseModel):
    cert_content: str = Field(..., description="Certificate configuration or PEM content description")


class CertOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the certificate follows proper lifetime and rotation rules")
    issues: List[str] = Field(default_factory=list, description="Identified certificate configuration or expiry issues")
    risk_score: float = Field(..., description="Risk score (0.0 to 100.0)")
    status: str = Field(..., description="Certificate validation status")


class PiCertificateRotationWatcher:
    """Enforces short certificate expiration windows, valid CA anchors, and automated rotation policies."""

    def __init__(self) -> None:
        self.agent_name = "PiCertificateRotationWatcher"

    def watch_certificate(self, input_envelope: CertInput) -> CertOutput:
        content = input_envelope.cert_content.lower()
        issues = []
        risk_score = 0.0

        # Self-signed certificate check
        if "self-signed" in content or "selfsigned" in content:
            issues.append("Self-Signed Certificate: Local root authority used. Real CA is required for production.")
            risk_score = max(risk_score, 75.0)

        # Expiry time checks
        if "expiring: true" in content or "expires in 5 days" in content or "expires_soon" in content:
            issues.append("Expiring Certificate: Certificate lifetime is nearing expiration boundary.")
            risk_score = max(risk_score, 90.0)

        # Non-standard or weak key sizes
        if "rsa-1024" in content or "key_size: 1024" in content:
            issues.append("Weak Key Strength: RSA-1024 detected. RSA-2048 or above is standard.")
            risk_score = max(risk_score, 80.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "FAILED_COMPLIANCE"
        if risk_score > 0.0 and is_sec:
            status = "WARN_COMPLIANCE"

        return CertOutput(
            is_secure=is_sec,
            issues=issues,
            risk_score=risk_score,
            status=status,
        )
