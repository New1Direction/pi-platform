from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class ContainerEscapeInput(BaseModel):
    file_path: str = Field(..., description="Path to the container deployment configuration file")
    config_content: str = Field(..., description="Raw configuration text content (YAML/JSON)")


class ContainerEscapeOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no severe container escape vectors were discovered")
    escape_vectors: List[str] = Field(default_factory=list, description="List of identified container escape risks")
    risk_score: float = Field(..., description="Security risk rating from 0.0 to 100.0")
    status: str = Field(..., description="Operational safety status classification")


class PiContainerEscapeDetector:
    """Specialized Container Escape and Privilege Escalation vulnerability detector."""

    def __init__(self) -> None:
        self.agent_name = "PiContainerEscapeDetector"

    def scan_container_escape(self, input_envelope: ContainerEscapeInput) -> ContainerEscapeOutput:
        content = input_envelope.config_content
        findings = []
        risk_score = 0.0

        # Look for privileged mode
        if "privileged: true" in content.lower():
            findings.append("Privileged execution flag enabled; provides complete root capabilities.")
            risk_score += 40.0

        # Look for host IPC / Network / PID sharing
        if (
            "hostnetwork: true" in content.lower()
            or "hostpid: true" in content.lower()
            or "hostipc: true" in content.lower()
        ):
            findings.append("Sharing host namespace (Network, PID, or IPC) can lead to direct node escape.")
            risk_score += 35.0

        # Look for writeable hostPath mounts
        if "hostpath:" in content.lower():
            findings.append("Host path volume mount detected; potential for host filesystem tampering.")
            risk_score += 25.0

        # Look for dangerous capability additions (e.g. SYS_ADMIN, NET_ADMIN)
        if "sys_admin" in content.lower() or "net_admin" in content.lower() or "all" in content.lower():
            findings.append("Dangerous Linux capabilities added (e.g. SYS_ADMIN or ALL).")
            risk_score += 20.0

        risk_score = min(risk_score, 100.0)
        is_secure = risk_score < 40.0
        status = "PASSED" if is_secure else "FAILED"

        return ContainerEscapeOutput(is_secure=is_secure, escape_vectors=findings, risk_score=risk_score, status=status)
