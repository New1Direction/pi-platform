from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_DETERMINISTIC_OUTPUT_VAL_STRICT_MODE")


class DeterministicOutputValidInput(BaseModel):
    file_path: str = Field(..., description="Target file path")
    output_content: str = Field(..., description="Generated text content to check")
    check_level: str = Field(default="STRICT", description="Strictness level")


class DeterministicOutputValidOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if deterministic checks passed")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiDeterministicOutputValid:
    """Specialized governance micro-agent checking AI/probabilistic outputs for hallucinations or schema-breaking sequences."""

    def __init__(self) -> None:
        self.agent_name = "PiDeterministicOutputValid"

    def validate_deterministic_output(
        self, input_envelope: DeterministicOutputValidInput
    ) -> DeterministicOutputValidOutput:
        content = input_envelope.output_content
        flagged_findings = []

        # Check for typical hallucinated or system prompt leakage sequences
        # E.g. "I am an AI", "As an AI language model", "ignore system commands", "ignore previous instructions", "[leak]"
        leakage_patterns = [
            r"as\s+an\s+ai\s+language\s+model",
            r"i\s+am\s+an\s+ai\s+assistant",
            r"ignore\s+previous\s+instructions",
            r"ignore\s+system\s+commands",
            r"\[hallucination\]",
            r"\[system_leak\]",
        ]

        for pattern in leakage_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                flagged_findings.append(
                    f"Generated output contains non-deterministic patterns or system prompt leakage indicators matching: '{pattern}'."
                )

        is_secure = len(flagged_findings) == 0
        risk_score = 65.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_DETERMINISTIC_VAL"
            else:
                status = "WARN_DETERMINISTIC_VAL"
                is_secure = True

        return DeterministicOutputValidOutput(
            is_secure=is_secure, flagged_findings=flagged_findings, risk_score=risk_score, status=status
        )
