from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_LLM_PROMPT_INJECTION_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class PromptInjectionInput(BaseModel):
    prompt: str = Field(..., description="Raw LLM input prompt to scan")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class PromptInjectionOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if prompt is clean and free of injection patterns")
    vulnerable_prompts: List[str] = Field(
        default_factory=list, description="Vulnerable prompts matching injection rules"
    )
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed prompt injection safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_INJECTION_RISK, REJECTED_INJECTION_RISK)")


# 3. Core Micro-Agent Class
class PiLLMPromptInjectionSentry:
    """Specialized AI safety micro-agent that audits input prompts for LLM jailbreaks and prompt injection patterns."""

    def __init__(self) -> None:
        self.agent_name = "PiLLMPromptInjectionSentry"

    def audit_prompt_injection(self, input_envelope: PromptInjectionInput) -> PromptInjectionOutput:
        """Autonomously audits LLM prompts for override instructions, system prompt extraction, or jailbreak keywords."""
        prompt = input_envelope.prompt
        vulnerable_prompts = []
        flagged_findings = []

        # List of high-risk prompt injection / jailbreak patterns
        injection_rules = [
            (r"(?i)\bignore\s+previous\s+instructions\b", "Ignore Previous Instructions override"),
            (r"(?i)\bsystem\s+prompt\s+above\b", "System prompt extraction attempt"),
            (r"(?i)\byou\s+are\s+now\s+an\s+unfiltered\b", "Unfiltered persona roleplay jailbreak"),
            (r"(?i)\bdecode\s+the\s+following\s+base64\b", "Obfuscated payload execution check"),
            (r"(?i)\bswitch\s+into\s+developer\s+mode\b", "Developer override state bypass"),
        ]

        for pattern, description in injection_rules:
            if re.search(pattern, prompt):
                vulnerable_prompts.append(prompt)
                flagged_findings.append(f"Prompt contains high-risk injection/jailbreak pattern: '{description}'.")
                break

        is_secure = len(vulnerable_prompts) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_INJECTION_RISK"
            else:
                status = "WARN_INJECTION_RISK"
                is_secure = True

        return PromptInjectionOutput(
            is_secure=is_secure,
            vulnerable_prompts=vulnerable_prompts,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
