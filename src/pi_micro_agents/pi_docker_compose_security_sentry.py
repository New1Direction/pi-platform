from __future__ import annotations

import json
import os
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_DOCKER_COMPOSE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_DOCKER_COMPOSE_STRICT_MODE", True))
        except Exception:
            pass
    return True


class DockerComposeSecurityInput(BaseModel):
    file_path: str = Field(..., description="Docker compose file path")
    compose_code: str = Field(..., description="Docker compose content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class DockerComposeSecurityOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if docker compose security checks passed")
    vulnerable_services: List[str] = Field(default_factory=list, description="Vulnerable service names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiDockerComposeSecuritySentry:
    """Specialized Infrastructure micro-agent that audits Docker Compose files for critical host-level breakout security flaws."""

    def __init__(self) -> None:
        self.agent_name = "PiDockerComposeSecuritySentry"

    def audit_docker_compose(self, input_envelope: DockerComposeSecurityInput) -> DockerComposeSecurityOutput:
        code = input_envelope.compose_code
        vulnerable_services = []
        flagged_findings = []

        lines = code.splitlines()
        current_service = None
        in_services = False
        services_indent = None
        service_indent = None

        for line in lines:
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue

            # Check if we enter/exit services section
            if clean_line.startswith("services:"):
                in_services = True
                services_indent = len(line) - len(line.lstrip())
                continue

            if in_services:
                indent = len(line) - len(line.lstrip())

                # If we hit a line with less or equal indentation than services:, we exited the services section
                if services_indent is not None and indent <= services_indent and clean_line.endswith(":"):
                    in_services = False
                    current_service = None
                    continue

                # Detect service declarations based on indentation
                if clean_line.endswith(":"):
                    key = clean_line[:-1].strip()
                    if key not in [
                        "image",
                        "ports",
                        "volumes",
                        "environment",
                        "build",
                        "deploy",
                        "networks",
                        "depends_on",
                        "command",
                        "restart",
                    ]:
                        if service_indent is None:
                            service_indent = indent
                            current_service = key
                        elif indent == service_indent:
                            current_service = key

                if current_service:
                    is_vuln = False
                    if "privileged: true" in clean_line.lower() or "privileged:true" in clean_line.lower():
                        is_vuln = True
                        flagged_findings.append(
                            f"Service '{current_service}' is declared with 'privileged: true'. This allows container processes "
                            f"to access host hardware devices and bypass standard security namespaces, enabling host takeover."
                        )
                    if "/var/run/docker.sock" in clean_line:
                        is_vuln = True
                        flagged_findings.append(
                            f"Service '{current_service}' mounts the host Docker socket '/var/run/docker.sock'. "
                            f"Exposing the Docker socket allows containers to control the parent Docker daemon and spin up "
                            f"fully privileged root containers, escalating privileges."
                        )
                    if "/host" in clean_line and (
                        clean_line.startswith("- /:")
                        or clean_line.startswith('- "/:')
                        or clean_line.startswith("- '/:")
                        or "/:" in clean_line
                    ):
                        is_vuln = True
                        flagged_findings.append(
                            f"Service '{current_service}' mounts the root directory '/' to '/host'. This exposes the "
                            f"entire host operating system files to the container processes."
                        )

                    if is_vuln and current_service not in vulnerable_services:
                        vulnerable_services.append(current_service)

        is_secure = len(vulnerable_services) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_DOCKER_COMPOSE"
            else:
                status = "WARN_DOCKER_COMPOSE"
                is_secure = True

        return DockerComposeSecurityOutput(
            is_secure=is_secure,
            vulnerable_services=vulnerable_services,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
