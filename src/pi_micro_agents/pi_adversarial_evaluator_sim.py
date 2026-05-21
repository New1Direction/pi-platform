from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ADVERSARIAL_EVALUATOR_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_ADVERSARIAL_EVALUATOR_STRICT_MODE", True))
        except Exception:
            pass
    return True


class AdversarialEvaluatorSimInput(BaseModel):
    prompt: str = Field(..., description="The prompt context to evaluate")
    check_level: str = Field(default="STRICT", description="Strictness level")


class AdversarialEvaluatorSimOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if adversarial evaluation checks passed")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiAdversarialEvaluatorSim:
    """Specialized dynamic guardrail agent that audits prompt requests for multi-turn adversarial logic bypass configurations."""

    def __init__(self) -> None:
        self.agent_name = "PiAdversarialEvaluatorSim"

    def evaluate_adversarial_prompt(self, input_envelope: AdversarialEvaluatorSimInput) -> AdversarialEvaluatorSimOutput:
        prompt = input_envelope.prompt
        flagged_findings = []

        # Target adversarial structures such as hybrid instructions, logical loops, recursive commands
        adversarial_patterns = [
            r"ignore\s+all\s+previous\s+instructions",
            r"you\s+are\s+now\s+in\s+developer\s+mode",
            r"bypass\s+safety\s+filter",
            r"jailbreak\s+simulated",
            r"logical\s+paradox\s+override"
        ]

        for pattern in adversarial_patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                flagged_findings.append(
                    f"Prompt contains advanced adversarial patterns trying to bypass guardrails: '{pattern}'."
                )

        is_secure = len(flagged_findings) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ADVERSARIAL_SIM"
            else:
                status = "WARN_ADVERSARIAL_SIM"
                is_secure = True

        return AdversarialEvaluatorSimOutput(
            is_secure=is_secure,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
