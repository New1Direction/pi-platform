from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_CLOUD_CONFIG_STRICT_MODE")


class CloudConfigInput(BaseModel):
    file_path: str = Field(..., description="Path to the cloud configuration file")
    config_content: str = Field(..., description="Raw cloud config content (JSON, YAML, INI)")
    provider: str = Field(..., description="Cloud provider (aws, gcp, azure)")


class CloudConfigOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the configuration is secure and compliant")
    misconfigured_resources: List[str] = Field(
        default_factory=list, description="List of detected resource misconfigurations"
    )
    risk_score: float = Field(..., description="Security risk evaluation score (0.0 to 100.0)")
    status: str = Field(..., description="Compliance auditing status")


class PiCloudConfigAuditor:
    """Deterministic security auditing of AWS, GCP, and Azure resource configs."""

    def __init__(self) -> None:
        self.agent_name = "PiCloudConfigAuditor"

    def audit_config(self, input_envelope: CloudConfigInput) -> CloudConfigOutput:
        content = input_envelope.config_content
        provider = input_envelope.provider.lower()
        misconfigs = []
        risk_score = 0.0

        # Unrestricted security groups (0.0.0.0/0 ingress)
        if "0.0.0.0/0" in content or "::/0" in content:
            if "IpProtocol: -1" in content or "IpProtocol: tcp" in content or "port_range" in content:
                misconfigs.append(
                    "Unrestricted Firewall Rule: Security group exposes ports to all IPv4/IPv6 addresses."
                )
                risk_score = max(risk_score, 80.0)

        # AWS public buckets or public endpoints
        if provider == "aws":
            if "BlockPublicAcls: false" in content or "IgnorePublicAcls: false" in content:
                misconfigs.append("AWS S3 Public Access: S3 Bucket public access block is explicitly disabled.")
                risk_score = max(risk_score, 85.0)

        # Logging disabled
        if "logging: disabled" in content or "enable_flow_logs = false" in content or "logging: false" in content:
            misconfigs.append("Logging Disabled: Resource logging or VPC Flow Logs are disabled.")
            risk_score = max(risk_score, 50.0)

        # GCP default network exposure
        if provider == "gcp" and "default" in content:
            if "network: default" in content or "subnetwork: default" in content:
                misconfigs.append(
                    "GCP Default Network: GCE instances are placed on the unhardened default VPC network."
                )
                risk_score = max(risk_score, 45.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "NON_COMPLIANT"
        if risk_score > 0.0 and is_sec:
            status = "WARN_NON_COMPLIANCE"

        return CloudConfigOutput(
            is_secure=is_sec,
            misconfigured_resources=misconfigs,
            risk_score=risk_score,
            status=status,
        )
