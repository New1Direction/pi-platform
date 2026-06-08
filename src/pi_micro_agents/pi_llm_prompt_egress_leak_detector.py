from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_LLM_PROMPT_EGRESS_LEAK_STRICT_MODE")


class LLMPromptEgressLeakInput(BaseModel):
    prompt: str = Field(..., description="The model generation or prompt text to audit for leaks")
    check_level: str = Field(default="STRICT", description="Strictness level")


class LLMPromptEgressLeakOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if no private data leaks are detected")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiLLMPromptEgressLeakDetector:
    """Specialized AI safety micro-agent that audits egress payload strings for private details (keys, credit cards, SSNs)."""

    def __init__(self) -> None:
        self.agent_name = "PiLLMPromptEgressLeakDetector"

    def audit_egress_leak(self, input_envelope: LLMPromptEgressLeakInput) -> LLMPromptEgressLeakOutput:
        prompt = input_envelope.prompt
        flagged_findings = []

        leak_patterns = {
            "AWS API Key": r"AKIA[0-9A-Z]{16}",
            "Private Key": r"-----BEGIN\s+PRIVATE\s+KEY-----",
            "Generic Secret / Token": r"api[-_]?key|secret[-_]?token|bearer\s+[a-zA-Z0-9_\-\.]+",
            "Credit Card": r"\b[3-6][0-9]{11,15}\b",
            "Social Security Number": r"\b\d{3}-\d{2}-\d{4}\b",
        }

        is_secure = True
        for name, pattern in leak_patterns.items():
            if re.search(pattern, prompt, re.IGNORECASE):
                is_secure = False
                flagged_findings.append(f"Egress leak detected: Content matches pattern for '{name}'.")

        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_LLM_PROMPT_EGRESS_LEAK"
            else:
                status = "WARN_LLM_PROMPT_EGRESS_LEAK"
                is_secure = True

        return LLMPromptEgressLeakOutput(
            is_secure=is_secure, flagged_findings=flagged_findings, risk_score=risk_score, status=status
        )
