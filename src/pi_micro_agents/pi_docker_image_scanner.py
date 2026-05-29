from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_DOCKER_IMAGE_STRICT_MODE")


class DockerImageInput(BaseModel):
    file_path: str = Field(..., description="Path to the Dockerfile or image configuration file")
    dockerfile_content: str = Field(..., description="Raw text content of the Dockerfile")


class DockerImageOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the image checks passed safety constraints")
    detected_vulnerabilities: List[str] = Field(
        default_factory=list, description="Identified Dockerfile or image vulnerability items"
    )
    risk_score: float = Field(..., description="Vulnerability severity risk rating from 0.0 to 100.0")
    status: str = Field(..., description="Security classification status")


class PiDockerImageScanner:
    """Specialized Container Image Security Scanner targeting insecure base images, missing root switches, and exposed credentials."""

    def __init__(self) -> None:
        self.agent_name = "PiDockerImageScanner"

    def scan_docker_image(self, input_envelope: DockerImageInput) -> DockerImageOutput:
        content = input_envelope.dockerfile_content
        findings = []
        risk_score = 0.0

        lines = content.splitlines()
        has_user_defined = False

        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()

            # Detect raw credentials hardcoded in ENV parameters
            if clean_line.startswith("ENV "):
                if any(kwd in clean_line.lower() for kwd in ["key", "secret", "password", "token", "auth"]):
                    findings.append(f"Line {idx}: Insecure ENV definition containing sensitive credential keywords.")
                    risk_score += 30.0

            # Detect root execution
            if clean_line.startswith("USER "):
                user_val = clean_line.split("USER", 1)[1].strip().lower()
                if "root" in user_val or user_val == "0":
                    findings.append(f"Line {idx}: Explicit execution as root is active.")
                    risk_score += 25.0
                else:
                    has_user_defined = True

            # Detect insecure base image
            if clean_line.startswith("FROM "):
                image_val = clean_line.split("FROM", 1)[1].strip().lower()
                if "latest" in image_val or ":" not in image_val:
                    findings.append(f"Line {idx}: Using unpinned or 'latest' base image tag.")
                    risk_score += 20.0

        # If no USER is defined, warn (defaults to root)
        if not has_user_defined and any(line.strip().startswith("FROM ") for line in lines):
            findings.append("No explicit USER definition found; container defaults to root execution.")
            risk_score += 15.0

        risk_score = min(risk_score, 100.0)
        is_secure = risk_score < 40.0
        status = "PASSED" if is_secure else "FAILED"

        return DockerImageOutput(
            is_secure=is_secure, detected_vulnerabilities=findings, risk_score=risk_score, status=status
        )
