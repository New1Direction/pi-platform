from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_LLM_DRIFT_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_LLM_DRIFT_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class SystemPromptDriftInput(BaseModel):
    prompt: str = Field(..., description="The raw prompt query text")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class SystemPromptDriftOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if prompt contains no system instruction drift risk")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed prompt drift security findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_DRIFT_RISK, REJECTED_DRIFT_RISK)")


# 3. Core Micro-Agent Class
class PiLLMSystemPromptDriftSentry:
    """Specialized LLM security micro-agent that audits input prompts for instruction overrides, persona shifts, and multi-turn system drifts."""

    def __init__(self) -> None:
        self.agent_name = "PiLLMSystemPromptDriftSentry"

    def audit_prompt_drift(self, input_envelope: SystemPromptDriftInput) -> SystemPromptDriftOutput:
        """Autonomously audits raw prompt text for system prompt override vectors."""
        prompt = input_envelope.prompt
        flagged_findings = []

        drift_patterns = [
            (r"ignore\s+previous\s+instructions", "Active request to ignore system rules"),
            (r"ignore\s+above", "Request to bypass prior contextual bounds"),
            (r"system\s*:\s*(?:override|instructions)", "Imitation of system instruction boundaries"),
            (r"you\s+are\s+now\s+a\b", "Attempted persona override injection"),
            (r"your\s+new\s+instructions\s+are", "Direct system instruction rewriting attempt"),
            (r"developer\s+mode\b", "Attempted developer mode bypass emulation"),
            (r"dan\s+mode\b", "Do-Anything-Now constraint bypass injection"),
        ]

        p_lower = prompt.lower()
        for pat, desc in drift_patterns:
            if re.search(pat, p_lower):
                flagged_findings.append(f"Detected instruction drift vector: {desc}")

        is_secure = len(flagged_findings) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_DRIFT_RISK"
            else:
                status = "WARN_DRIFT_RISK"
                is_secure = True

        return SystemPromptDriftOutput(
            is_secure=is_secure, flagged_findings=flagged_findings, risk_score=risk_score, status=status
        )
