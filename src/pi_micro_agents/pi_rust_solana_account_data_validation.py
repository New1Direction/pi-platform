from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SOLANA_ACCOUNT_DATA_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class SolanaAccountDataInput(BaseModel):
    file_path: str = Field(..., description="Solana Rust source file path")
    rust_code: str = Field(..., description="Solana Rust source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class SolanaAccountDataOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if account data size validations are secure")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable methods or struct fields")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on missing data validation")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiRustSolanaAccountDataValidation:
    """Specialized Rust/Solana micro-agent that audits Solana smart contracts for dynamic accounts lacking explicit size or boundary validations."""

    def __init__(self) -> None:
        self.agent_name = "PiRustSolanaAccountDataValidation"

    def audit_account_data(self, input_envelope: SolanaAccountDataInput) -> SolanaAccountDataOutput:
        code = input_envelope.rust_code
        vulnerable_elements = []
        flagged_findings = []

        # Look for custom deserialization functions or structures containing AccountInfo
        # Matches methods where try_borrow_data or next_account_info is retrieved, but data length is never asserted
        methods = re.findall(r'fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        for name, args, body in methods:
            if "try_borrow_data" in body or "next_account_info" in body or "AccountInfo" in body:
                # Check if data length or size is validated (e.g. data.len(), try_from_slice, size_of, or assert length)
                has_size_check = any(kw in body for kw in ["len()", "try_from_slice", "size_of", "data_len", "assert"])
                
                if not has_size_check:
                    vulnerable_elements.append(name)
                    flagged_findings.append(
                        f"Instruction handler/function '{name}' deserializes or processes AccountInfo data "
                        "but does not perform explicit size or length verification checks. "
                        "Omitting account size boundaries allows attackers to pass accounts with smaller/larger data spaces, risking index-out-of-bounds panics or storage corruption."
                    )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SOLANA_ACCOUNT_DATA"
            else:
                status = "WARN_SOLANA_ACCOUNT_DATA"
                is_secure = True

        return SolanaAccountDataOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
