from __future__ import annotations
import os
import re
from typing import List
from pydantic import BaseModel, Field

def is_strict_mode() -> bool:
    env_val = os.getenv("PI_TO_PRD_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True

class ToPrdInput(BaseModel):
    prd_content: str = Field(..., description="PRD file markdown content")

class ToPrdOutput(BaseModel):
    is_secure: bool = Field(..., description="True if PRD is semantically valid")
    failed_sections: List[str] = Field(default_factory=list, description="Sections that fail PRD specifications")
    risk_score: float = Field(..., description="Calculated risk score")
    status: str = Field(..., description="Status (PASSED, REJECTED_TO_PRD, WARN_TO_PRD)")

class PiToPrdValidator:
    """Deterministic micro-agent that checks PRDs for defined objectives and functional scope boundaries."""

    def __init__(self) -> None:
        self.agent_name = "PiToPrdValidator"

    def validate_prd(self, input_envelope: ToPrdInput) -> ToPrdOutput:
        content = input_envelope.prd_content
        failed = []
        
        sections = [
            (["objective", "goal"], "Objective or Goal section"),
            (["non-goal", "out of scope"], "Non-Goals section"),
            (["requirement", "specification", "spec"], "Requirements or Functional Specifications section"),
            (["verification", "validation", "success criteria"], "Verification or Success Criteria section")
        ]
        
        for keywords, section_name in sections:
            if not any(kw in content.lower() for kw in keywords):
                failed.append(section_name)
                
        is_secure = len(failed) == 0
        risk_score = 85.0 if not is_secure else 0.0
        
        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_TO_PRD"
            else:
                status = "WARN_TO_PRD"
                is_secure = True
                
        return ToPrdOutput(
            is_secure=is_secure,
            failed_sections=failed,
            risk_score=risk_score,
            status=status
        )
