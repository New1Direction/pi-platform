from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_DOCKER_SOCKET_PRIVILEGE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class DockerSocketPrivilegeInput(BaseModel):
    file_path: str = Field(..., description="Dockerfile or run config file path")
    dockerfile_code: str = Field(..., description="Docker build/run configuration content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class DockerSocketPrivilegeOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if no Docker socket mounts or privileges exist")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable commands or lines")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiDockerSocketPrivilegeSentry:
    """Specialized Infrastructure micro-agent that audits configurations mounting /var/run/docker.sock."""

    def __init__(self) -> None:
        self.agent_name = "PiDockerSocketPrivilegeSentry"

    def audit_docker_socket(self, input_envelope: DockerSocketPrivilegeInput) -> DockerSocketPrivilegeOutput:
        code = input_envelope.dockerfile_code
        vulnerable_elements = []
        flagged_findings = []

        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            if "docker.sock" in line:
                vulnerable_elements.append(f"Line {idx}")
                flagged_findings.append(
                    f"Line {idx}: Reference to Docker socket mount detected: '{line.strip()}'. "
                    "Mounting the Docker socket inside a container allows escalation of privilege to full host takeover."
                )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_DOCKER_SOCKET_PRIVILEGE"
            else:
                status = "WARN_DOCKER_SOCKET_PRIVILEGE"
                is_secure = True

        return DockerSocketPrivilegeOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
