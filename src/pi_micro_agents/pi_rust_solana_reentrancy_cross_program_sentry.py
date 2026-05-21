from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SOLANA_REENTRANCY_CROSS_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class SolanaReentrancyCrossInput(BaseModel):
    file_path: str = Field(..., description="Solana Rust source file path")
    rust_code: str = Field(..., description="Solana Rust source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class SolanaReentrancyCrossOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if cross-program reentrancy risks are addressed")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable methods or code blocks")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on CPI reentrancy risks")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiRustSolanaReentrancyCrossProgramSentry:
    """Specialized Rust/Solana micro-agent that audits CPI execution patterns to prevent state reentrancy."""

    def __init__(self) -> None:
        self.agent_name = "PiRustSolanaReentrancyCrossProgramSentry"

    def audit_reentrancy_cross(self, input_envelope: SolanaReentrancyCrossInput) -> SolanaReentrancyCrossOutput:
        code = input_envelope.rust_code
        vulnerable_elements = []
        flagged_findings = []

        methods = re.findall(r'fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        for name, args, body in methods:
            if "invoke" in body or "invoke_signed" in body:
                # CPI invocation exists. Let's check if there is state mutation *after* the invoke
                # Simple check: matches variable mutations or borrows (e.g. `*` or `mut` or `=` or `serialize`) after invoke
                parts = re.split(r'invoke(_signed)?\s*\(', body)
                if len(parts) > 1:
                    post_cpi_code = parts[-1]
                    if "=" in post_cpi_code or "mut " in post_cpi_code or "serialize" in post_cpi_code:
                        vulnerable_elements.append(name)
                        flagged_findings.append(
                            f"Instruction handler '{name}' invokes CPI before finalizing its internal state mutations. "
                            "Solana transactions are atomic, but executing external programs before completing local updates risks semantic state confusion or reentrancy vulnerability."
                        )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 70.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SOLANA_REENTRANCY_CROSS"
            else:
                status = "WARN_SOLANA_REENTRANCY_CROSS"
                is_secure = True

        return SolanaReentrancyCrossOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
