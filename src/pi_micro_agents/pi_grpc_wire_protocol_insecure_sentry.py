from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_GRPC_WIRE_PROTOCOL_INSECURE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class GrpcWireProtocolInsecureInput(BaseModel):
    file_path: str = Field(..., description="API or gRPC client file path")
    code_content: str = Field(..., description="gRPC implementation code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class GrpcWireProtocolInsecureOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if gRPC channels enforce TLS/SSL")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable lines or methods")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiGrpcWireProtocolInsecureSentry:
    """Specialized API Auth micro-agent that audits gRPC client channels to verify TLS transport security."""

    def __init__(self) -> None:
        self.agent_name = "PiGrpcWireProtocolInsecureSentry"

    def audit_grpc_insecure(self, input_envelope: GrpcWireProtocolInsecureInput) -> GrpcWireProtocolInsecureOutput:
        code = input_envelope.code_content
        vulnerable_elements = []
        flagged_findings = []

        # Find gRPC channel creation, e.g. grpc.insecure_channel or insecure_channel
        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            if "insecure_channel" in clean_line or "credentials=None" in clean_line:
                vulnerable_elements.append(f"Line {idx}")
                flagged_findings.append(
                    f"Line {idx}: Insecure gRPC channel definition detected: '{clean_line}'. "
                    "Unencrypted gRPC communication permits network-level wire interception or eavesdropping."
                )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_GRPC_WIRE_PROTOCOL_INSECURE"
            else:
                status = "WARN_GRPC_WIRE_PROTOCOL_INSECURE"
                is_secure = True

        return GrpcWireProtocolInsecureOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
