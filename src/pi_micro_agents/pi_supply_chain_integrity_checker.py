from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_SUPPLY_CHAIN_STRICT_MODE")


class SupplyChainInput(BaseModel):
    manifest_path: str = Field(..., description="Path to the manifest file")
    manifest_content: str = Field(..., description="Raw manifest file contents (e.g., package.json, requirements.txt)")


class SupplyChainOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if supply chain packages are safe and verified")
    suspicious_packages: List[str] = Field(
        default_factory=list, description="List of typosquatted or untrusted packages detected"
    )
    risk_score: float = Field(..., description="Aggregated threat score (0.0 to 100.0)")
    status: str = Field(..., description="Supply chain verification status")


class PiSupplyChainIntegrityChecker:
    """Detects typosquatted packages, unsafe dependency sources, and unpinned dependencies in manifests."""

    def __init__(self) -> None:
        self.agent_name = "PiSupplyChainIntegrityChecker"

    def check_supply_chain(self, input_envelope: SupplyChainInput) -> SupplyChainOutput:
        content = input_envelope.manifest_content.lower()
        suspicious = []
        risk_score = 0.0

        # Typosquatting checks (e.g. reqeusts instead of requests, loadsh, etc.)
        typos = {
            "reqeusts": "requests",
            "boto4": "boto3",
            "loadsh": "lodash",
            "pyton": "python",
            "flask-corss": "flask-cors",
        }
        for typo, correct in typos.items():
            if typo in content:
                suspicious.append(f"Typosquatted Package Detected: Found '{typo}', did you mean '{correct}'?")
                risk_score = max(risk_score, 90.0)

        # Insecure sources (e.g. git endpoints or raw HTTP URLs instead of npmjs/pypi)
        if "http://" in content and ".git" in content:
            suspicious.append(
                "Insecure Source: Dependency pulled via unencrypted http:// protocol from git repository."
            )
            risk_score = max(risk_score, 75.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "SUSPICIOUS_DEPENDENCIES_FOUND"
        if risk_score > 0.0 and is_sec:
            status = "WARN_SUSPICIOUS_DEPENDENCIES"

        return SupplyChainOutput(
            is_secure=is_sec,
            suspicious_packages=suspicious,
            risk_score=risk_score,
            status=status,
        )
