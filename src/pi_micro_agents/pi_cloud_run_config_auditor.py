from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field


class CloudRunConfigInput(BaseModel):
    service_yaml: str = Field(..., description="Raw YAML text of the Cloud Run service configuration")
    allow_unauthenticated: bool = Field(
        default=False,
        description="Whether unauthenticated invocations (allUsers binding) are explicitly allowed",
    )


class CloudRunConfigOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no high-risk security flaws are detected")
    issues: List[str] = Field(default_factory=list, description="List of identified configuration risks")
    risk_score: float = Field(..., description="Security risk score from 0.0 to 100.0")
    status: str = Field(..., description="Audit status: PASS, WARN, or FAIL")


class PiCloudRunConfigAuditor:
    """Audits Cloud Run Service YAML configurations using safe regex-based parsing to enforce VPC connection, secret management, non-root execution, probes, and resource bounds."""

    def __init__(self) -> None:
        self.agent_name = "PiCloudRunConfigAuditor"

    def execute(self, input_envelope: CloudRunConfigInput) -> CloudRunConfigOutput:
        """Analyze Cloud Run YAML text for security and operations best practices."""
        yaml_content = input_envelope.service_yaml
        allow_unauthenticated = input_envelope.allow_unauthenticated

        issues = []
        risk_score = 0.0

        # 1. Check for allowUnauthenticated / allUsers ingress setting
        if not allow_unauthenticated and (
            "allusers" in yaml_content.lower() or "allowunauthenticated: true" in yaml_content.lower()
        ):
            issues.append("VULNERABILITY: Public unauthenticated ingress is active (allUsers binding).")
            risk_score += 30.0

        # 2. Check for resource limits
        if "resources:" not in yaml_content.lower() or "limits:" not in yaml_content.lower():
            issues.append("WARNING: Service does not configure resource limits (CPU/Memory).")
            risk_score += 20.0

        # 3. Check for VPC connection
        if "vpc-access-connector" not in yaml_content.lower() and "vpc-access" not in yaml_content.lower():
            issues.append("WARNING: Service does not utilize a VPC connector; it might bypass secure network routing.")
            risk_score += 15.0

        # 4. Check for health probes
        if "livenessprobe" not in yaml_content.lower() and "startupprobe" not in yaml_content.lower():
            issues.append("WARNING: Service does not configure livenessProbe or startupProbe for health checks.")
            risk_score += 10.0

        # 5. Non-root context
        if "runasnonroot: true" not in yaml_content.lower() and "securitycontext" not in yaml_content.lower():
            issues.append("WARNING: Service does not enforce non-root container execution.")
            risk_score += 10.0

        # 6. Check for cleartext secrets in environment variables
        env_blocks = re.findall(r"(?s)-\s*name:\s*([^\n]+).*?value:\s*([^\n]+)", yaml_content)
        sensitive_keywords = ["password", "secret", "token", "key", "credential", "auth"]
        for env_name, env_val in env_blocks:
            env_name_clean = env_name.strip(" '\"").lower()
            env_val_clean = env_val.strip(" '\"")
            if any(kw in env_name_clean for kw in sensitive_keywords):
                if env_val_clean and not env_val_clean.startswith("$") and "valuefrom" not in env_val_clean.lower():
                    issues.append(f"WARNING: Sensitive environment variable '{env_name.strip()}' has cleartext value.")
                    risk_score += 25.0
                    break

        risk_score = min(risk_score, 100.0)
        is_secure = risk_score < 50.0

        if risk_score >= 60.0:
            status = "FAIL"
        elif risk_score >= 30.0:
            status = "WARN"
        else:
            status = "PASS"

        return CloudRunConfigOutput(
            is_secure=is_secure,
            issues=issues,
            risk_score=risk_score,
            status=status,
        )
