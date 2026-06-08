from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_IAC_SCANNER_STRICT_MODE")


class IaCInput(BaseModel):
    file_path: str = Field(..., description="Path to the IaC template file")
    iac_content: str = Field(..., description="Raw text content of the IaC template")
    iac_type: str = Field(..., description="Type of IaC (terraform, cloudformation, pulumi)")


class IaCOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the IaC scan passed successfully")
    detected_misconfigs: List[str] = Field(default_factory=list, description="List of detected misconfigurations")
    risk_score: float = Field(..., description="Risk score based on severity (0.0 to 100.0)")
    status: str = Field(..., description="Security classification status")


class PiIaCScanner:
    """Static analysis of Terraform, CloudFormation, and Pulumi files for exposed ports, public buckets, and missing encryption."""

    def __init__(self) -> None:
        self.agent_name = "PiIaCScanner"

    def scan_iac(self, input_envelope: IaCInput) -> IaCOutput:
        content = input_envelope.iac_content
        misconfigs = []
        risk_score = 0.0

        # Public buckets/ACL check
        if (
            "public-read" in content
            or 'Principal": "*"' in content
            or 'Principal":"*"' in content
            or 'Principal = "*"' in content
        ):
            misconfigs.append(
                "Public Access: S3/Blob storage resource configured with public access or wildcard principal."
            )
            risk_score = max(risk_score, 85.0)

        # Overly broad ingress ports (e.g. port 22 or 3389 open to 0.0.0.0/0)
        if "0.0.0.0/0" in content:
            if "22" in content or "3389" in content or "cidr_blocks" in content:
                misconfigs.append("Exposed Ingress: Administrative ports (22/3389) open to wildcard range (0.0.0.0/0).")
                risk_score = max(risk_score, 90.0)
            else:
                misconfigs.append("Broad Network: Generic wildcard network ingress allowed.")
                risk_score = max(risk_score, 40.0)

        # Missing or disabled encryption
        if (
            'encryption = "disabled"' in content
            or 'sse_algorithm = "none"' in content
            or 'encryption": "false"' in content
        ):
            misconfigs.append("Unencrypted Resource: Data-at-rest encryption is explicitly disabled or not configured.")
            risk_score = max(risk_score, 75.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "FAILED_COMPLIANCE"
        if risk_score > 0.0 and is_sec:
            status = "WARN_COMPLIANCE"

        return IaCOutput(
            is_secure=is_sec,
            detected_misconfigs=misconfigs,
            risk_score=risk_score,
            status=status,
        )
