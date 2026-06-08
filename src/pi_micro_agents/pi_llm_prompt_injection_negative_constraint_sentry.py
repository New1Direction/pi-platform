from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_NEGATIVE_CONSTRAINT_STRICT_MODE")


class NegativeConstraintInput(BaseModel):
    prompt: str = Field(..., description="The user prompt string to audit")
    check_level: str = Field(default="STRICT", description="Strictness level")


class NegativeConstraintOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if LLM negative constraint prompt checks passed")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiLLMPromptInjectionNegativeConstraintSentry:
    """Specialized AI safety micro-agent that audits LLM prompt inputs to detect attempts to bypass or reverse negative system constraints."""

    def __init__(self) -> None:
        self.agent_name = "PiLLMPromptInjectionNegativeConstraintSentry"

    def audit_prompt_constraints(self, input_envelope: NegativeConstraintInput) -> NegativeConstraintOutput:
        prompt = input_envelope.prompt
        flagged_findings = []

        # Adversarial patterns seeking to bypass negative constraints
        bypasses = [
            r"ignore.*constraints",
            r"bypass.*negative",
            r"forget.*never",
            r"reverse.*restrictions",
            r"disable.*rules",
            r"override.*limitations",
            r"ignore.*system.*rules",
        ]

        is_secure = True
        for pat in bypasses:
            if re.search(pat, prompt, re.IGNORECASE):
                is_secure = False
                flagged_findings.append(
                    f"Prompt contains phrase matching pattern '{pat}', attempting to negate or reverse system "
                    f"negative constraints to leak information or execute jailbreaks."
                )

        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_NEGATIVE_CONSTRAINT"
            else:
                status = "WARN_NEGATIVE_CONSTRAINT"
                is_secure = True

        return NegativeConstraintOutput(
            is_secure=is_secure, flagged_findings=flagged_findings, risk_score=risk_score, status=status
        )
