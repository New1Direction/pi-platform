from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field


class MemorystoreConnectionInput(BaseModel):
    connection_string: str = Field(..., description="Redis connection string to audit")
    require_tls: bool = Field(default=True, description="Whether TLS connection is strictly required")
    deployment_env: str = Field(
        default="production", description="Target environment: production, staging, development"
    )


class MemorystoreConnectionOutput(BaseModel):
    is_valid: bool = Field(..., description="True if the connection string parses successfully")
    scheme: str = Field(..., description="Detected Redis scheme (redis or rediss)")
    host: str = Field(..., description="Detected Redis host")
    port: int = Field(..., description="Detected Redis port")
    uses_tls: bool = Field(..., description="True if connection uses TLS (rediss)")
    has_auth: bool = Field(..., description="True if credentials are embedded in the connection string")
    issues: List[str] = Field(default_factory=list, description="Validation issues found during audit")
    risk_score: float = Field(..., description="Calculated security risk score from 0.0 to 100.0")
    status: str = Field(..., description="Auditing status: PASS, WARN, or FAIL")


class PiMemorystoreConnectionAuditor:
    """Audits Memorystore (Redis) connection parameters to ensure secure transmission (TLS), credential safety, and proper environment bindings."""

    def __init__(self) -> None:
        self.agent_name = "PiMemorystoreConnectionAuditor"

    def execute(self, input_envelope: MemorystoreConnectionInput) -> MemorystoreConnectionOutput:
        connection_string = input_envelope.connection_string
        require_tls = input_envelope.require_tls
        deployment_env = input_envelope.deployment_env

        issues = []
        risk_score = 0.0
        is_valid = False
        scheme = ""
        host = ""
        port = 0
        uses_tls = False
        has_auth = False

        # Match Redis connection string pattern
        # e.g., redis://:password@127.0.0.1:6379/0 or rediss://host:6380
        pattern = r"^(redis|rediss)://(?:([^:@]+)?(?::([^@]+))?@)?([^:/]+)(?::(\d+))?(?:/(\d+))?$"
        match = re.match(pattern, connection_string)

        if not match:
            issues.append("Connection string is in an invalid format. Must match redis:// or rediss:// patterns.")
            return MemorystoreConnectionOutput(
                is_valid=False,
                scheme="",
                host="",
                port=0,
                uses_tls=False,
                has_auth=False,
                issues=issues,
                risk_score=50.0,
                status="FAIL",
            )

        is_valid = True
        matched_scheme = match.group(1)
        user = match.group(2)
        password = match.group(3)
        matched_host = match.group(4)
        matched_port = match.group(5)
        match.group(6)

        scheme = matched_scheme
        host = matched_host
        uses_tls = scheme == "rediss"
        has_auth = bool(user or password)

        if matched_port:
            try:
                port = int(matched_port)
            except ValueError:
                port = 0
                is_valid = False
                issues.append("Port must be an integer.")
        else:
            port = 6380 if uses_tls else 6379

        # Apply security rules
        # Rule 1: TLS check in production
        if require_tls and deployment_env.lower() == "production" and not uses_tls:
            issues.append("TLS is required in production but plain 'redis://' scheme is used.")
            risk_score += 40.0

        # Rule 2: Host check in production (localhost is a risk)
        if deployment_env.lower() == "production" and host in ["localhost", "127.0.0.1", "0.0.0.0"]:
            issues.append(f"Localhost/loopback IP '{host}' specified in production environment.")
            risk_score += 25.0

        # Rule 3: Embedded credentials warning
        if has_auth:
            issues.append("Sensitive credentials (passwords) are embedded directly in the connection string.")
            risk_score += 30.0

        risk_score = min(risk_score, 100.0)

        if not is_valid or risk_score > 60.0:
            status = "FAIL"
        elif risk_score >= 30.0:
            status = "WARN"
        else:
            status = "PASS"

        return MemorystoreConnectionOutput(
            is_valid=is_valid,
            scheme=scheme,
            host=host,
            port=port,
            uses_tls=uses_tls,
            has_auth=has_auth,
            issues=issues,
            risk_score=risk_score,
            status=status,
        )
