from __future__ import annotations
import os
import re
from typing import List
from pydantic import BaseModel, Field

def is_strict_mode() -> bool:
    env_val = os.getenv("PI_TDD_MOCK_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True

class TddMockingInput(BaseModel):
    test_code_content: str = Field(..., description="Test suite source code")

class TddMockingOutput(BaseModel):
    is_secure: bool = Field(..., description="True if mock layers are thin and safe")
    over_mocked_lines: List[str] = Field(default_factory=list, description="Lines containing broad mock statements")
    risk_score: float = Field(..., description="Mocking safety risk score")
    status: str = Field(..., description="Status (PASSED, REJECTED_TDD_MOCK, WARN_TDD_MOCK)")

class PiTddMockingSanityChecker:
    """Deterministic micro-agent that flags excessively broad mock patches in tests."""

    def __init__(self) -> None:
        self.agent_name = "PiTddMockingSanityChecker"

    def check_mocking_sanity(self, input_envelope: TddMockingInput) -> TddMockingOutput:
        code = input_envelope.test_code_content
        flagged = []
        
        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            # Look for broad mocks, e.g. mock.patch.dict or mock.Mock() returning itself broadly
            if "mock.patch" in clean or "MagicMock" in clean or "Mock(" in clean or "mock.Mock" in clean:
                if "spec=" not in clean and "autospec=" not in clean:
                    flagged.append(f"Line {idx}: Broad mock statement lacking spec validation: '{clean}'")
                    
        is_secure = len(flagged) < 3  # Allow up to 2 unspec'd mocks per file, reject beyond that
        risk_score = 70.0 if not is_secure else 0.0
        
        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_TDD_MOCK"
            else:
                status = "WARN_TDD_MOCK"
                is_secure = True
                
        return TddMockingOutput(
            is_secure=is_secure,
            over_mocked_lines=flagged,
            risk_score=risk_score,
            status=status
        )
