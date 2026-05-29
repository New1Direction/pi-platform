from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ZK_DIV_BY_ZERO_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class ZKDivByZeroConstraintInput(BaseModel):
    file_path: str = Field(..., description="Circom source file path")
    circom_code: str = Field(..., description="Circom source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ZKDivByZeroConstraintOutput(BaseModel):
    is_secure: bool = Field(
        ..., description="Indicates if Circom division operations are guarded against divisor zeroing"
    )
    vulnerable_signals: List[str] = Field(default_factory=list, description="Vulnerable signal or variable names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed findings on zero divisor constraints"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiZKDivByZeroConstraintAuditor:
    """Specialized ZK micro-agent that audits Circom templates for division expressions lacking non-zero divisor constraints."""

    def __init__(self) -> None:
        self.agent_name = "PiZKDivByZeroConstraintAuditor"

    def audit_div_by_zero(self, input_envelope: ZKDivByZeroConstraintInput) -> ZKDivByZeroConstraintOutput:
        code = input_envelope.circom_code
        vulnerable_signals = []
        flagged_findings = []

        templates = re.findall(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for tname, _params, body in templates:
            # Find any division statement, e.g. a / b
            div_matches = re.finditer(r"([a-zA-Z0-9_]+)\s*(?:/|\\)\s*([a-zA-Z0-9_]+)", body)
            for match in div_matches:
                divisor = match.group(2)

                # Check if divisor has non-zero assertions/constraints
                has_nonzero_constraint = re.search(rf"{divisor}\s*!==?\s*0", body) or re.search(
                    rf"assert\s*\(\s*{divisor}\s*!=?\s*0\s*\)", body
                )

                if not has_nonzero_constraint:
                    vulnerable_signals.append(divisor)
                    flagged_findings.append(
                        f"Template '{tname}': Division using divisor '{divisor}' "
                        "lacks an explicit non-zero constraint. This could lead to arithmetic failure or malicious provers exploiting zero division."
                    )

        is_secure = len(vulnerable_signals) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ZK_DIV_BY_ZERO"
            else:
                status = "WARN_ZK_DIV_BY_ZERO"
                is_secure = True

        return ZKDivByZeroConstraintOutput(
            is_secure=is_secure,
            vulnerable_signals=vulnerable_signals,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
