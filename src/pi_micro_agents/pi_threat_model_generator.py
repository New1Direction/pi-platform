from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_SYSTEM_STRICT_MODE")


class SystemInput(BaseModel):
    system_desc: str = Field(..., description="High-level description of system components, databases, and clients")


class ThreatModelOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if system has acceptable threat levels")
    threats: List[str] = Field(default_factory=list, description="Identified threat scenarios based on design elements")
    STRIDE_categories: List[str] = Field(
        default_factory=list, description="Relevant STRIDE threat model categories mapped"
    )
    risk_score: float = Field(..., description="Overall calculated architectural threat score")
    status: str = Field(..., description="Architectural status")


class PiThreatModelGenerator:
    """Generates threat models for high-level system configurations utilizing standard STRIDE methodology."""

    def __init__(self) -> None:
        self.agent_name = "PiThreatModelGenerator"

    def generate_threat_model(self, input_envelope: SystemInput) -> ThreatModelOutput:
        desc = input_envelope.system_desc.lower()
        threats = []
        categories = []
        risk_score = 0.0

        # Database related threats
        if "database" in desc or "db" in desc or "storage" in desc:
            threats.append(
                "Information Disclosure: Potential compromise of sensitive user databases due to weak access policies."
            )
            categories.append("Information Disclosure")
            threats.append(
                "Tampering: Malicious injection or truncation queries executed directly on storage clusters."
            )
            categories.append("Tampering")
            risk_score = max(risk_score, 60.0)

        # API related threats
        if "api" in desc or "endpoint" in desc or "gateway" in desc:
            threats.append("Elevation of Privilege: Unauthenticated attackers abusing broken authorization boundaries.")
            categories.append("Elevation of Privilege")
            threats.append(
                "Denial of Service: Volumetric request bursts exhausting thread pools or backend CPU limits."
            )
            categories.append("Denial of Service")
            risk_score = max(risk_score, 80.0)

        # Public web interface
        if "public web" in desc or "frontend" in desc or "client" in desc:
            threats.append("Spoofing: Phishing portals imitating production client domain names.")
            categories.append("Spoofing")
            risk_score = max(risk_score, 50.0)

        # Ensure categories are unique
        categories = list(set(categories))

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "THREATS_IDENTIFIED"
        if risk_score > 0.0 and is_sec:
            status = "WARN_THREATS"

        return ThreatModelOutput(
            is_secure=is_sec,
            threats=threats,
            STRIDE_categories=categories,
            risk_score=risk_score,
            status=status,
        )
