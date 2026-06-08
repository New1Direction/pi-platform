from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ZEROIZE_STRICT_MODE")


class MemoryZeroizeInput(BaseModel):
    file_path: str = Field(..., description="C/C++/Rust file path")
    source_code: str = Field(..., description="Source code content")
    sensitive_symbols: List[str] = Field(..., description="Sensitive secret buffers/structures")


class MemoryZeroizeOutput(BaseModel):
    is_secure: bool = Field(..., description="True if secure zeroization APIs are correctly applied")
    flagged_findings: List[str] = Field(
        default_factory=list, description="List of unzeroized or elidable wipe instances"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status (PASSED, WARN_ZEROIZE_RISK, REJECTED_ZEROIZE_RISK)")


class PiMemoryZeroizeSentry:
    """Specialized memory-lifetime micro-agent verifying zeroization API safety."""

    def __init__(self) -> None:
        self.agent_name = "PiMemoryZeroizeSentry"

    def audit_memory_zeroize(self, input_envelope: MemoryZeroizeInput) -> MemoryZeroizeOutput:
        code = input_envelope.source_code
        symbols = input_envelope.sensitive_symbols
        findings = []

        # Approved secure wipe tokens
        secure_wipes = ["explicit_bzero", "SecureZeroMemory", "sodium_memzero", "memset_s", "Zeroize"]

        for symbol in symbols:
            # Check if symbol appears in code
            if symbol in code:
                # Find occurrences of standard memset that can be optimized away
                memset_patterns = re.findall(r"memset\s*\(\s*" + re.escape(symbol) + r"\s*,", code)
                for _ in memset_patterns:
                    findings.append(
                        f"Symbol '{symbol}' is cleared with standard 'memset'. This call can be optimized away "
                        "by compiler Dead-Store Elimination (DSE). Use 'explicit_bzero' or similar."
                    )

                # Check if it lacks any secure wipes completely
                has_secure_wipe = any(wipe in code for wipe in secure_wipes)
                if not has_secure_wipe and not memset_patterns:
                    findings.append(f"Sensitive variable '{symbol}' is never securely zeroized before leaving scope.")

        is_secure = len(findings) == 0
        risk_score = 80.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            status = "REJECTED_ZEROIZE_RISK" if is_strict_mode() else "WARN_ZEROIZE_RISK"
            if not is_strict_mode():
                is_secure = True

        return MemoryZeroizeOutput(is_secure=is_secure, flagged_findings=findings, risk_score=risk_score, status=status)
