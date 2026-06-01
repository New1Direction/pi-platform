from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field


class StructuredLoggingInput(BaseModel):
    file_path: str = Field(..., description="Path to the source code file being inspected")
    code_content: str = Field(..., description="Raw code contents of the file")


class StructuredLoggingOutput(BaseModel):
    is_secure: bool = Field(..., description="True if code adheres perfectly to structured logging guidelines")
    unstructured_statements: List[str] = Field(
        default_factory=list, description="List of identified unstructured logging/print lines"
    )
    compliance_score: float = Field(..., description="Compliance percentage rating from 0.0 to 100.0")
    status: str = Field(..., description="Structured logging compliance status classification")


class PiStructuredLoggingEnforcer:
    """Specialized linter enforcing structured/JSON logging across source code and flagging plain print statements."""

    def __init__(self) -> None:
        self.agent_name = "PiStructuredLoggingEnforcer"

    def enforce_structured_logging(self, input_envelope: StructuredLoggingInput) -> StructuredLoggingOutput:
        content = input_envelope.code_content
        findings = []
        deductions = 0.0

        # Scan for raw 'print(' statements
        print_re = re.compile(r"\bprint\s*\(")
        for idx, line in enumerate(content.splitlines(), 1):
            if print_re.search(line) and not line.strip().startswith("#"):
                findings.append(f"Line {idx}: print used")
                deductions += 15.0

        compliance_score = max(100.0 - deductions, 0.0)
        is_secure = compliance_score >= 90.0
        status = "COMPLIANT" if is_secure else "NON_COMPLIANT"

        return StructuredLoggingOutput(
            is_secure=is_secure, unstructured_statements=findings, compliance_score=compliance_score, status=status
        )
