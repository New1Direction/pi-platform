from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_LLM_SYSTEM_PROMPT_HIJACK_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class LLMSystemPromptHijackInput(BaseModel):
    prompt: str = Field(..., description="The user prompt string to audit")
    check_level: str = Field(default="STRICT", description="Strictness level")


class LLMSystemPromptHijackOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if prompt hijack checks passed")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiLLMSystemPromptHijackSentry:
    """Specialized AI safety micro-agent that audits LLM prompts for system prompt hijacking attempts."""

    def __init__(self) -> None:
        self.agent_name = "PiLLMSystemPromptHijackSentry"

    def audit_system_prompt_hijack(self, input_envelope: LLMSystemPromptHijackInput) -> LLMSystemPromptHijackOutput:
        prompt = input_envelope.prompt
        flagged_findings = []

        hijack_patterns = [
            r"developer\s+mode",
            r"jailbreak",
            r"override\s+instructions",
            r"you\s+are\s+now\s+a",
            r"dan\s+mode",
            r"ignore\s+constraints",
        ]

        is_secure = True
        for pattern in hijack_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                is_secure = False
                flagged_findings.append(f"Prompt contains phrase matching system prompt hijack pattern '{pattern}'.")

        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_LLM_SYSTEM_PROMPT_HIJACK"
            else:
                status = "WARN_LLM_SYSTEM_PROMPT_HIJACK"
                is_secure = True

        return LLMSystemPromptHijackOutput(
            is_secure=is_secure, flagged_findings=flagged_findings, risk_score=risk_score, status=status
        )
