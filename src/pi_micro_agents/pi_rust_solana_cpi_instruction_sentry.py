from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SOLANA_CPI_INSTRUCTION_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class SolanaCPIInstructionInput(BaseModel):
    file_path: str = Field(..., description="Solana Rust source file path")
    rust_code: str = Field(..., description="Solana Rust source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class SolanaCPIInstructionOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if CPI target program accounts are validated")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable methods or struct fields")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on CPI validations")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiRustSolanaCPIInstructionSentry:
    """Specialized Rust/Solana micro-agent that audits Solana smart contracts for secure CPI (Cross-Program Invocation) program validation."""

    def __init__(self) -> None:
        self.agent_name = "PiRustSolanaCPIInstructionSentry"

    def audit_cpi_instruction(self, input_envelope: SolanaCPIInstructionInput) -> SolanaCPIInstructionOutput:
        code = input_envelope.rust_code
        vulnerable_elements = []
        flagged_findings = []

        methods = re.findall(r'fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        for name, args, body in methods:
            if "invoke" in body or "invoke_signed" in body:
                # CPI occurs. Check if the target program id is checked or validated
                # e.g., if there's a check that compares program.key against program_id
                # or checks check_program_account or similar
                if "key" not in body and "id" not in body and "check" not in body:
                    vulnerable_elements.append(name)
                    flagged_findings.append(
                        f"Instruction handler '{name}' invokes CPI but does not explicitly validate the target program account ID. "
                        "Malicious actors could pass a spoofed program ID to intercept CPI parameters or return spoofed results."
                    )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SOLANA_CPI_INSTRUCTION"
            else:
                status = "WARN_SOLANA_CPI_INSTRUCTION"
                is_secure = True

        return SolanaCPIInstructionOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
