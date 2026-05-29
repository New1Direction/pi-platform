from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_DIVIDE_BEFORE_MULTIPLY_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class DivideBeforeMultiplyInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class DivideBeforeMultiplyOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract math division order is secure")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed findings on division before multiplication"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityDivideBeforeMultiplyAuditor:
    """Specialized Web3 micro-agent that audits contracts to prevent precision loss caused by division before multiplication."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityDivideBeforeMultiplyAuditor"

    def audit_divide_multiply(self, input_envelope: DivideBeforeMultiplyInput) -> DivideBeforeMultiplyOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            # Check for division followed by multiplication, e.g. a / b * c, or a.div(b).mul(c)
            # Match pattern: division operator '/' followed by multiplication '*'
            # Or safe math methods: .div(...) followed by .mul(...)
            has_operator_issue = re.search(r"\b[a-zA-Z0-9_]+\s*/\s*[a-zA-Z0-9_]+\s*\*\s*[a-zA-Z0-9_]+\b", body)
            has_safemath_issue = re.search(r"\.div\s*\(.*?\)\s*\.mul\s*\(", body)

            if has_operator_issue or has_safemath_issue:
                vulnerable_funcs.append(name)
                flagged_findings.append(
                    f"Function '{name}' performs division before multiplication in a math expression. "
                    "Solidity does not support floating point numbers; performing division first truncates the fractional part, leading to severe precision loss."
                )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 70.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_DIVIDE_BEFORE_MULTIPLY"
            else:
                status = "WARN_DIVIDE_BEFORE_MULTIPLY"
                is_secure = True

        return DivideBeforeMultiplyOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
