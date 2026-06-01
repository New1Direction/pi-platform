from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ZERO_TRUST_STRICT_MODE")


class ZeroTrustInput(BaseModel):
    network_policy_content: str = Field(
        ..., description="Raw text of network policy, ingress boundaries, or IAM service mappings"
    )


class ZeroTrustOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the network topology adheres to Zero-Trust policies")
    violations: List[str] = Field(default_factory=list, description="Identified Zero-Trust architecture violations")
    risk_score: float = Field(..., description="Calculated security risk rating (0.0 to 100.0)")
    status: str = Field(..., description="Zero-Trust validation status")


class PiZeroTrustVerifier:
    """Validates service connectivity restrictions, ingress/egress rules, and mutual TLS controls to enforce Zero-Trust."""

    def __init__(self) -> None:
        self.agent_name = "PiZeroTrustVerifier"

    def verify_zero_trust(self, input_envelope: ZeroTrustInput) -> ZeroTrustOutput:
        content = input_envelope.network_policy_content.lower()
        violations = []
        risk_score = 0.0

        # Allow all traffic / wildcard network egress
        if "ingress: []" in content or "egress: []" in content or "from: *" in content or "to: *" in content:
            violations.append(
                "Implicit Trust Boundaries: Broad wildcard access rules enable implicit service traversal."
            )
            risk_score = max(risk_score, 80.0)

        # Insecure transit communication protocols
        if "http://" in content or "ftp://" in content or "telnet" in content:
            violations.append("Insecure Protocol Transit: Plaintext service communication discovered inside boundary.")
            risk_score = max(risk_score, 85.0)

        # Missing mutual TLS enforcement
        if "mtls: false" in content or "require_mtls = false" in content:
            violations.append("Missing Mutual Authentication: mTLS enforcement is explicitly disabled or turned off.")
            risk_score = max(risk_score, 70.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "FAILED_ZERO_TRUST_COMPLIANCE"
        if risk_score > 0.0 and is_sec:
            status = "WARN_ZERO_TRUST"

        return ZeroTrustOutput(
            is_secure=is_sec,
            violations=violations,
            risk_score=risk_score,
            status=status,
        )
