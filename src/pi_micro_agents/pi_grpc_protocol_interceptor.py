from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_GRPC_PROTOCOL_INTERCEPT_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_GRPC_PROTOCOL_INTERCEPT_STRICT_MODE", True))
        except Exception:
            pass
    return True


class GrpcProtocolInterceptInput(BaseModel):
    file_path: str = Field(..., description="Protobuf or Python source file path")
    grpc_code: str = Field(..., description="File content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class GrpcProtocolInterceptOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if gRPC wire protocol checks passed")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable endpoints or hooks")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiGrpcProtocolInterceptor:
    """Specialized gRPC micro-agent that audits service definitions and configuration files for unencrypted payloads or insecure transport options."""

    def __init__(self) -> None:
        self.agent_name = "PiGrpcProtocolInterceptor"

    def audit_grpc_interceptor(self, input_envelope: GrpcProtocolInterceptInput) -> GrpcProtocolInterceptOutput:
        code = input_envelope.grpc_code
        vulnerable_elements = []
        flagged_findings = []

        # Scans for insecure credentials configuration or plain text gRPC options
        # E.g. insecure_channel, insecure_credentials, insecure_server_credentials, grpc.insecure
        insecure_match = re.search(
            r"(insecure_channel|insecure_credentials|insecure_server_credentials|insecure_port|InsecureChannel|insecure_connector)",
            code,
        )

        if insecure_match:
            vulnerable_elements.append(insecure_match.group(1))
            flagged_findings.append(
                f"gRPC implementation uses an unencrypted wire transmission setup: '{insecure_match.group(1)}'. "
                f"Establishing unencrypted connections exposes high-performance RPC streams to wiretapping "
                f"and active intercept compromises."
            )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_GRPC_INTERCEPT"
            else:
                status = "WARN_GRPC_INTERCEPT"
                is_secure = True

        return GrpcProtocolInterceptOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
