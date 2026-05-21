from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SOLANA_OWNER_VERIFICATION_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class SolanaOwnerVerificationInput(BaseModel):
    file_path: str = Field(..., description="Solana Rust source file path")
    rust_code: str = Field(..., description="Solana Rust source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class SolanaOwnerVerificationOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if account owner verification checks are present")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable methods or struct fields")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on missing owner checks")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiRustSolanaOwnerVerificationGuard:
    """Specialized Rust/Solana micro-agent that audits instruction endpoints for missing Account Owner verification checks."""

    def __init__(self) -> None:
        self.agent_name = "PiRustSolanaOwnerVerificationGuard"

    def audit_owner_verification(self, input_envelope: SolanaOwnerVerificationInput) -> SolanaOwnerVerificationOutput:
        code = input_envelope.rust_code
        vulnerable_elements = []
        flagged_findings = []

        methods = re.findall(r'fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        for name, args, body in methods:
            if "AccountInfo" in args or "AccountInfo" in body:
                # If there are user accounts, check if the owner is checked
                if "owner" not in body and "program_id" not in body and "Owner" not in body:
                    vulnerable_elements.append(name)
                    flagged_findings.append(
                        f"Instruction handler '{name}' processes accounts but does not verify account owners. "
                        "Without verifying that the account's owner is the expected program ID, malicious actors can pass spoofed state accounts."
                    )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SOLANA_OWNER_VERIFICATION"
            else:
                status = "WARN_SOLANA_OWNER_VERIFICATION"
                is_secure = True

        return SolanaOwnerVerificationOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
