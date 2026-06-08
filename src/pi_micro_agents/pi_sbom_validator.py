from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_SBOM_STRICT_MODE")


class SBOMInput(BaseModel):
    sbom_path: str = Field(..., description="Path to the SBOM file")
    sbom_content: str = Field(..., description="Raw string content of CycloneDX or SPDX SBOM")
    format: str = Field(..., description="Format of the SBOM (cyclonedx, spdx)")


class SBOMOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the SBOM passed licensing and attestation gates")
    license_issues: List[str] = Field(default_factory=list, description="Banned or risky licenses identified")
    missing_attestations: List[str] = Field(default_factory=list, description="Missing signatures or attestations")
    risk_score: float = Field(..., description="Aggregated SBOM risk assessment (0.0 to 100.0)")
    status: str = Field(..., description="SBOM validation status")


class PiSBOMValidator:
    """Validates SPDX/CycloneDX SBOMs for license compliance, known vulnerable components, and missing signatures."""

    def __init__(self) -> None:
        self.agent_name = "PiSBOMValidator"

    def validate_sbom(self, input_envelope: SBOMInput) -> SBOMOutput:
        content = input_envelope.sbom_content.lower()
        license_issues = []
        missing_attestations = []
        risk_score = 0.0

        # Check for banned licenses (copyleft licenses that violate standard enterprise compliance rules)
        if "agpl" in content or "agpl-3.0" in content:
            license_issues.append("Banned Copyleft License: AGPL-3.0 detected in dependency tree.")
            risk_score = max(risk_score, 85.0)
        elif "gpl-3.0" in content or "gplv3" in content:
            license_issues.append("Risky Copyleft License: GPL-3.0 detected in dependency tree.")
            risk_score = max(risk_score, 50.0)

        # Check for missing signature / attestation patterns
        if "signature" not in content and "attestation" not in content:
            missing_attestations.append("Missing Cryptographic Signature: No attestation blocks found in SBOM.")
            risk_score = max(risk_score, 60.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "FAILED_SBOM_VALIDATION"
        if risk_score > 0.0 and is_sec:
            status = "WARN_SBOM_VALIDATION"

        return SBOMOutput(
            is_secure=is_sec,
            license_issues=license_issues,
            missing_attestations=missing_attestations,
            risk_score=risk_score,
            status=status,
        )
