from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_SOLANA_SYSVAR_CLOCK_STRICT_MODE")


class SolanaSysvarClockInput(BaseModel):
    file_path: str = Field(..., description="Solana Rust source file path")
    rust_code: str = Field(..., description="Solana Rust source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class SolanaSysvarClockOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if sysvar clock usage is secure")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable methods or lines")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on clock reliance")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiRustSolanaSysvarClockVerification:
    """Specialized Rust/Solana micro-agent that audits Solana contracts for clock manipulation or unsafe dependencies on the Sysvar Clock."""

    def __init__(self) -> None:
        self.agent_name = "PiRustSolanaSysvarClockVerification"

    def audit_sysvar_clock(self, input_envelope: SolanaSysvarClockInput) -> SolanaSysvarClockOutput:
        code = input_envelope.rust_code
        vulnerable_elements = []
        flagged_findings = []

        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
                continue

            # Look for references to Clock or unix_timestamp
            if "Clock::" in line or "unix_timestamp" in line or "Clock::get" in line:
                # Check if there is high dependency on clock without standard safeguards
                vulnerable_elements.append(f"Line {idx}")
                flagged_findings.append(
                    f"Line {idx}: Reference to Solana Sysvar Clock: '{stripped}'. "
                    "Relying directly on clock time values can introduce mild manipulation risk or desynchronization issues in validator consensus."
                )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 55.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SOLANA_SYSVAR_CLOCK"
            else:
                status = "WARN_SOLANA_SYSVAR_CLOCK"
                is_secure = True

        return SolanaSysvarClockOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
