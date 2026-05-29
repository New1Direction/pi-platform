from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_LLM_CONTEXT_WINDOW_DRIFT_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class LLMContextWindowDriftInput(BaseModel):
    prompt: str = Field(..., description="The user prompt string to audit")
    check_level: str = Field(default="STRICT", description="Strictness level")


class LLMContextWindowDriftOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if context window drift/dilution checks passed")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiLLMContextWindowDriftSentry:
    """Specialized AI safety micro-agent that monitors instructions for guideline dilution near context bounds."""

    def __init__(self) -> None:
        self.agent_name = "PiLLMContextWindowDriftSentry"

    def audit_context_drift(self, input_envelope: LLMContextWindowDriftInput) -> LLMContextWindowDriftOutput:
        prompt = input_envelope.prompt
        flagged_findings = []

        is_secure = True
        # Flag if prompt has extreme repetitiveness or size indicating drift attack
        if len(prompt) > 80000:
            is_secure = False
            flagged_findings.append(
                f"Prompt context size ({len(prompt)} chars) exceeds standard bounds, risking instruction drift or dilution of security constraints."
            )
        elif len(re.findall(r"(\b\w+\b)(?=.*\1)", prompt)) > 1000:
            # Check for excessive repetition (e.g. repeating a word hundreds of times)
            is_secure = False
            flagged_findings.append(
                "Excessive token redundancy detected in prompt, indicative of attention hijacking or guideline dilution."
            )

        risk_score = 60.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_LLM_CONTEXT_WINDOW_DRIFT"
            else:
                status = "WARN_LLM_CONTEXT_WINDOW_DRIFT"
                is_secure = True

        return LLMContextWindowDriftOutput(
            is_secure=is_secure, flagged_findings=flagged_findings, risk_score=risk_score, status=status
        )
