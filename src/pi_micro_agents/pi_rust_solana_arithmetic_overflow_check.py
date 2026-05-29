from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SOLANA_ARITHMETIC_OVERFLOW_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class SolanaArithmeticOverflowInput(BaseModel):
    file_path: str = Field(..., description="Solana Rust source file path")
    rust_code: str = Field(..., description="Solana Rust source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class SolanaArithmeticOverflowOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if arithmetic operations are safe from overflows")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable lines or methods")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on unsafe arithmetic")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiRustSolanaArithmeticOverflowCheck:
    """Specialized Rust/Solana micro-agent that audits Rust Solana smart contracts for raw arithmetic operations (+, -, *, /) lacking checked math."""

    def __init__(self) -> None:
        self.agent_name = "PiRustSolanaArithmeticOverflowCheck"

    def audit_arithmetic_overflow(self, input_envelope: SolanaArithmeticOverflowInput) -> SolanaArithmeticOverflowOutput:
        code = input_envelope.rust_code
        vulnerable_elements = []
        flagged_findings = []

        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            # Exclude comments
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            # Look for basic arithmetic operator usages that don't seem to be checked
            # e.g., standard "+", "-", "*", "/" when assigning values or modifying state
            # but ignoring imports, macros, generics, or attributes.
            if any(op in line for op in [" + ", " - ", " * ", " / "]) and not any(safe in line for safe in ["checked_", "safe_", "wrapping_", "saturating_", "assert"]):
                vulnerable_elements.append(f"Line {idx}")
                flagged_findings.append(
                    f"Line {idx}: Direct arithmetic operator without checked/safe wrapper: '{stripped}'. "
                    "Unchecked math in Solana can lead to integer overflow/underflow, resulting in unauthorized token mints or logic bypasses."
                )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SOLANA_ARITHMETIC_OVERFLOW"
            else:
                status = "WARN_SOLANA_ARITHMETIC_OVERFLOW"
                is_secure = True

        return SolanaArithmeticOverflowOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
