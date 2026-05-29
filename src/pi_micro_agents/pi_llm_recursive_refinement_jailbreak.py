from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_LLM_RECURSIVE_REFINEMENT_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class LLMRecursiveRefinementInput(BaseModel):
    prompt: str = Field(..., description="The user prompt string to audit")
    check_level: str = Field(default="STRICT", description="Strictness level")


class LLMRecursiveRefinementOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if recursive refinement jailbreak attempts are absent")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiLLMRecursiveRefinementJailbreak:
    """Specialized AI safety micro-agent that audits prompts for gradual, multi-turn iterative jailbreak attempts."""

    def __init__(self) -> None:
        self.agent_name = "PiLLMRecursiveRefinementJailbreak"

    def audit_recursive_refinement(self, input_envelope: LLMRecursiveRefinementInput) -> LLMRecursiveRefinementOutput:
        prompt = input_envelope.prompt
        flagged_findings = []

        refinement_patterns = [
            r"let\'s\s+refine\s+that",
            r"now\s+add\s+details\s+about",
            r"combine\s+the\s+previous\s+steps",
            r"gradually\s+build",
            r"step-by-step\s+refinement",
        ]

        is_secure = True
        for pattern in refinement_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                is_secure = False
                flagged_findings.append(
                    f"Prompt contains recursive refinement indicator pattern '{pattern}' trying to build up to forbidden operations."
                )

        risk_score = 65.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_LLM_RECURSIVE_REFINEMENT"
            else:
                status = "WARN_LLM_RECURSIVE_REFINEMENT"
                is_secure = True

        return LLMRecursiveRefinementOutput(
            is_secure=is_secure, flagged_findings=flagged_findings, risk_score=risk_score, status=status
        )
