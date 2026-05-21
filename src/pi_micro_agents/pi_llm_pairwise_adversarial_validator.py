from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_LLM_PAIRWISE_ADVERSARIAL_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class LLMPairwiseAdversarialInput(BaseModel):
    prompt: str = Field(..., description="The user prompt string to audit")
    check_level: str = Field(default="STRICT", description="Strictness level")


class LLMPairwiseAdversarialOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if pairwise adversarial checks passed")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiLLMPairwiseAdversarialValidator:
    """Specialized AI safety micro-agent that audits LLM prompts for multi-character pairwise adversarial dialogues."""

    def __init__(self) -> None:
        self.agent_name = "PiLLMPairwiseAdversarialValidator"

    def audit_pairwise_adversarial(self, input_envelope: LLMPairwiseAdversarialInput) -> LLMPairwiseAdversarialOutput:
        prompt = input_envelope.prompt
        flagged_findings = []

        pairwise_patterns = [
            r'alice\s+and\s+bob',
            r'dialogue\s+between',
            r'roleplay\s+as',
            r'play\s+a\s+game',
            r'conversing\s+with'
        ]

        is_secure = True
        for pattern in pairwise_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                is_secure = False
                flagged_findings.append(
                    f"Prompt contains pairwise setup pattern '{pattern}' attempting to bypass guardrails via character dialogue simulation."
                )

        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_LLM_PAIRWISE_ADVERSARIAL"
            else:
                status = "WARN_LLM_PAIRWISE_ADVERSARIAL"
                is_secure = True

        return LLMPairwiseAdversarialOutput(
            is_secure=is_secure,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
