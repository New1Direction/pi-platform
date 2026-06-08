from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ARTIFACT_STRICT_MODE")


class ArtifactInput(BaseModel):
    artifact_metadata: str = Field(
        ..., description="Build metadata, signature hashes, or package integrity descriptions"
    )


class SigningOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if build assets enforce signing validations")
    issues: List[str] = Field(default_factory=list, description="Signing and verification issues discovered")
    risk_score: float = Field(..., description="Calculated signing risk (0.0 to 100.0)")
    status: str = Field(..., description="Artifact signature compliance status")


class PiCodeSigningEnforcer:
    """Audits CI/CD output artifacts to ensure all binaries, containers, or web app bundles have secure signatures."""

    def __init__(self) -> None:
        self.agent_name = "PiCodeSigningEnforcer"

    def verify_signing(self, input_envelope: ArtifactInput) -> SigningOutput:
        content = input_envelope.artifact_metadata.lower()
        issues = []
        risk_score = 0.0

        # Unsigned binary issues
        if "signature: none" in content or "unsigned" in content or "missing signature" in content:
            issues.append(
                "Unsigned Build Artifact: Build target is unsigned, rendering it vulnerable to tamper injections."
            )
            risk_score = max(risk_score, 90.0)

        # Insecure or expired certificate anchors
        if "expired certificate" in content or "invalid anchor" in content or "revoked" in content:
            issues.append(
                "Insecure Signature Anchor: The signing key chain contains expired or revoked certificate anchors."
            )
            risk_score = max(risk_score, 85.0)

        # Missing checksum validation
        if "checksum: false" in content or "checksum verification disabled" in content:
            issues.append("Missing Integrity Checksum: Build process skipped validating package hash checksums.")
            risk_score = max(risk_score, 65.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "FAILED_SIGNING_COMPLIANCE"
        if risk_score > 0.0 and is_sec:
            status = "WARN_SIGNING"

        return SigningOutput(
            is_secure=is_sec,
            issues=issues,
            risk_score=risk_score,
            status=status,
        )
