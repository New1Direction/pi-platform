from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_DOCKER_COMPOSE_PORT_STRICT_MODE")


class DockerComposePortExposureInput(BaseModel):
    file_path: str = Field(..., description="Docker compose file path")
    compose_code: str = Field(..., description="Docker compose content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class DockerComposePortExposureOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if port mappings are secure")
    vulnerable_services: List[str] = Field(default_factory=list, description="Vulnerable service names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiDockerComposePortExposureSentry:
    """Specialized Infrastructure micro-agent that audits Docker Compose files for wildcards exposing admin/db ports."""

    def __init__(self) -> None:
        self.agent_name = "PiDockerComposePortExposureSentry"

    def audit_docker_compose_ports(
        self, input_envelope: DockerComposePortExposureInput
    ) -> DockerComposePortExposureOutput:
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

            if clean_line.startswith("services:"):
                in_services = True
                services_indent = len(line) - len(line.lstrip())
                continue

            if in_services:
                indent = len(line) - len(line.lstrip())

                if services_indent is not None and indent <= services_indent and clean_line.endswith(":"):
                    in_services = False
                    current_service = None
                    continue

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
                    # Look for port mapping lines like "- 0.0.0.0:80:80" or "- 3306:3306" or "- 5432:5432"
                    if clean_line.startswith("-") and (":" in clean_line):
                        # Wildcard ip or default binding of sensitive admin/db ports: 3306, 5432, 27017, 6379, 8080, 9200
                        sensitive_ports = ["3306", "5432", "27017", "6379", "8080", "9200", "22", "23", "9000"]
                        exposed_wildcard = "0.0.0.0" in clean_line or not any(
                            ip in clean_line for ip in ["127.0.0.1", "localhost"]
                        )

                        has_sensitive_port = any(port in clean_line for port in sensitive_ports)

                        if exposed_wildcard and has_sensitive_port:
                            vulnerable_services.append(current_service)
                            flagged_findings.append(
                                f"Service '{current_service}' exposes sensitive port mapping '{clean_line}' to public 0.0.0.0 interface. "
                                "This permits unauthorized external connectivity to administrative or database backends."
                            )

        is_secure = len(vulnerable_services) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_DOCKER_COMPOSE_PORT"
            else:
                status = "WARN_DOCKER_COMPOSE_PORT"
                is_secure = True

        return DockerComposePortExposureOutput(
            is_secure=is_secure,
            vulnerable_services=vulnerable_services,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
