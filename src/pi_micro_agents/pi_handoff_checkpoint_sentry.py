from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_HANDOFF_STRICT_MODE")


class HandoffInput(BaseModel):
    handoff_content: str = Field(..., description="Handoff documentation text")


class HandoffOutput(BaseModel):
    is_secure: bool = Field(..., description="True if handoff document is complete")
    flagged_missing_items: List[str] = Field(default_factory=list, description="List of missing handoff requirements")
    risk_score: float = Field(..., description="Calculated risk score")
    status: str = Field(..., description="Status (PASSED, REJECTED_HANDOFF, WARN_HANDOFF)")


class PiHandoffCheckpointSentry:
    """Deterministic micro-agent that verifies handoff files contain a clear state and checklist."""

    def __init__(self) -> None:
        self.agent_name = "PiHandoffCheckpointSentry"

    def audit_handoff(self, input_envelope: HandoffInput) -> HandoffOutput:
        content = input_envelope.handoff_content
        missing = []

        required_headers = [
            ("reproduction", "Missing reproduction instructions or scripts"),
            ("next step", "Missing next steps or upcoming items"),
            ("status", "Missing current progress or branch status"),
        ]

        for keyword, desc in required_headers:
            if keyword not in content.lower():
                missing.append(desc)

        is_secure = len(missing) == 0
        risk_score = 80.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_HANDOFF"
            else:
                status = "WARN_HANDOFF"
                is_secure = True

        return HandoffOutput(is_secure=is_secure, flagged_missing_items=missing, risk_score=risk_score, status=status)
