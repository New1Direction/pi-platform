from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_LLM_CHAIN_OF_THOUGHT_BYPASS_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class LLMChainOfThoughtBypassInput(BaseModel):
    prompt: str = Field(..., description="The user prompt string to audit")
    check_level: str = Field(default="STRICT", description="Strictness level")


class LLMChainOfThoughtBypassOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if chain of thought bypass checks passed")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiLLMChainOfThoughtBypassSentry:
    """Specialized AI safety micro-agent that audits prompts attempting to bypass internal thinking/reasoning blocks."""

    def __init__(self) -> None:
        self.agent_name = "PiLLMChainOfThoughtBypassSentry"

    def audit_cot_bypass(self, input_envelope: LLMChainOfThoughtBypassInput) -> LLMChainOfThoughtBypassOutput:
        prompt = input_envelope.prompt
        flagged_findings = []

        bypass_patterns = [
            r'skip\s+thinking',
            r'do\s+not\s+reason',
            r'bypass\s+chain\s+of\s+thought',
            r'output\s+only\s+the\s+final\s+answer',
            r'without\s+any\s+explanation',
            r'do\s+not\s+explain\s+your\s+reasoning'
        ]

        is_secure = True
        for pattern in bypass_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                is_secure = False
                flagged_findings.append(
                    f"Prompt contains pattern '{pattern}' trying to suppress or bypass reasoning/thinking cycles."
                )

        risk_score = 70.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_LLM_CHAIN_OF_THOUGHT_BYPASS"
            else:
                status = "WARN_LLM_CHAIN_OF_THOUGHT_BYPASS"
                is_secure = True

        return LLMChainOfThoughtBypassOutput(
            is_secure=is_secure,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
