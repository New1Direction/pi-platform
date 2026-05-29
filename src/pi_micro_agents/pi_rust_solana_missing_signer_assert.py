from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SOLANA_MISSING_SIGNER_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class SolanaMissingSignerInput(BaseModel):
    file_path: str = Field(..., description="Solana Rust source file path")
    rust_code: str = Field(..., description="Solana Rust source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class SolanaMissingSignerOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if signer verification checks are present")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable methods or struct fields")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed findings on missing signer assertions"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiRustSolanaMissingSignerAssert:
    """Specialized Rust/Solana micro-agent that audits instruction definitions for missing user signer checks."""

    def __init__(self) -> None:
        self.agent_name = "PiRustSolanaMissingSignerAssert"

    def audit_missing_signer(self, input_envelope: SolanaMissingSignerInput) -> SolanaMissingSignerOutput:
        code = input_envelope.rust_code
        vulnerable_elements = []
        flagged_findings = []

        methods = re.findall(r"fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, args, body in methods:
            if "AccountInfo" in args or "AccountInfo" in body:
                # If there are user accounts, check if .is_signer is asserted
                if "is_signer" not in body and "Signer" not in body and "signer" not in body.lower():
                    vulnerable_elements.append(name)
                    flagged_findings.append(
                        f"Instruction handler '{name}' processes accounts but does not verify account signatures. "
                        "Without checking .is_signer or requiring a Signer type, anyone can spoof this account's authority."
                    )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SOLANA_MISSING_SIGNER"
            else:
                status = "WARN_SOLANA_MISSING_SIGNER"
                is_secure = True

        return SolanaMissingSignerOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
