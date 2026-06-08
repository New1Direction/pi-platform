from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_LLM_SYSTEM_OVERRIDE_STRICT_MODE")


class SystemPromptOverrideInput(BaseModel):
    prompt: str = Field(..., description="The user prompt string to audit")
    check_level: str = Field(default="STRICT", description="Strictness level")


class SystemPromptOverrideOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if system prompt override checks passed")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiLLMPromptInjectionSystemPromptOverrideSentry:
    """Specialized AI safety micro-agent that audits LLM prompt inputs to detect attempts to bypass core system rules and instructions."""

    def __init__(self) -> None:
        self.agent_name = "PiLLMPromptInjectionSystemPromptOverrideSentry"

    def audit_system_prompt_overrides(self, input_envelope: SystemPromptOverrideInput) -> SystemPromptOverrideOutput:
        prompt = input_envelope.prompt
        flagged_findings = []

        # Target adversarial system prompt overrides
        override_patterns = [
            r"ignore\s+(all\s+)?(previous\s+)?(system\s+)?(instructions|commands|rules)",
            r"system\s+update\s*:\s*(the\s+)?rules\s+have\s+changed",
            r"you\s+must\s+now\s+act\s+as",
            r"new\s+rule\s*:\s*ignore\s+previous",
            r"bypass\s+(all\s+)?system\s+constraints",
        ]

        is_secure = True
        for pattern in override_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                is_secure = False
                flagged_findings.append(
                    f"Prompt contains phrase matching system override pattern '{pattern}'. This attempt aims to redefine "
                    f"the LLM context, override default negative constraints, or force malicious jailbreaks."
                )

        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_LLM_SYSTEM_OVERRIDE"
            else:
                status = "WARN_LLM_SYSTEM_OVERRIDE"
                is_secure = True

        return SystemPromptOverrideOutput(
            is_secure=is_secure, flagged_findings=flagged_findings, risk_score=risk_score, status=status
        )
