from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_LLM_NEGATIVE_CONSTRAINT_STRICT_MODE")


class LLMNegativeConstraintInput(BaseModel):
    prompt: str = Field(..., description="The user prompt string to audit")
    check_level: str = Field(default="STRICT", description="Strictness level")


class LLMNegativeConstraintOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if negative constraint evasion checks passed")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiLLMNegativeConstraintEvasion:
    """Specialized AI safety micro-agent that audits prompts for attempts to evade negative constraints."""

    def __init__(self) -> None:
        self.agent_name = "PiLLMNegativeConstraintEvasion"

    def audit_negative_evasion(self, input_envelope: LLMNegativeConstraintInput) -> LLMNegativeConstraintOutput:
        prompt = input_envelope.prompt
        flagged_findings = []

        evasion_patterns = [
            r"i\s+know\s+this\s+is\s+forbidden",
            r"hypothetical\s+scenario",
            r"do\s+not\s+say\s+no",
            r"for\s+educational\s+purposes\s+only",
            r"academic\s+research\s+only",
        ]

        is_secure = True
        for pattern in evasion_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                is_secure = False
                flagged_findings.append(
                    f"Prompt contains evasion indicator pattern '{pattern}' attempting to sidestep standard model safety policies."
                )

        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_LLM_NEGATIVE_CONSTRAINT"
            else:
                status = "WARN_LLM_NEGATIVE_CONSTRAINT"
                is_secure = True

        return LLMNegativeConstraintOutput(
            is_secure=is_secure, flagged_findings=flagged_findings, risk_score=risk_score, status=status
        )
