from __future__ import annotations
import os
import re
from typing import List
from pydantic import BaseModel, Field

def is_strict_mode() -> bool:
    env_val = os.getenv("PI_GRILL_ME_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True

class GrillMeInput(BaseModel):
    plan_content: str = Field(..., description="Implementation plan text")

class GrillMeOutput(BaseModel):
    is_secure: bool = Field(..., description="True if the plan is robust and complete")
    missing_prerequisites: List[str] = Field(default_factory=list, description="List of missing details or vague phrases")
    risk_score: float = Field(..., description="Calculated risk score")
    status: str = Field(..., description="Status (PASSED, REJECTED_GRILL_ME, WARN_GRILL_ME)")

class PiGrillMeQuestionnaire:
    """Deterministic micro-agent that grills proposed plans for vague details or empty placeholders."""

    def __init__(self) -> None:
        self.agent_name = "PiGrillMeQuestionnaire"

    def grill_plan(self, input_envelope: GrillMeInput) -> GrillMeOutput:
        plan = input_envelope.plan_content
        missing = []
        
        # Check for vague terms
        vague_terms = [
            (r"\betc\b", "Contains vague 'etc.'"),
            (r"\btbd\b", "Contains unresolved 'TBD'"),
            (r"\btodo\b", "Contains incomplete 'TODO'"),
            (r"\bplaceholder\b", "Contains 'placeholder' values"),
            (r"implement later", "Contains deferred implementation markers")
        ]
        
        for pat, desc in vague_terms:
            if re.search(pat, plan, flags=re.IGNORECASE):
                missing.append(desc)
                
        is_secure = len(missing) == 0
        risk_score = 90.0 if not is_secure else 0.0
        
        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_GRILL_ME"
            else:
                status = "WARN_GRILL_ME"
                is_secure = True
                
        return GrillMeOutput(
            is_secure=is_secure,
            missing_prerequisites=missing,
            risk_score=risk_score,
            status=status
        )
