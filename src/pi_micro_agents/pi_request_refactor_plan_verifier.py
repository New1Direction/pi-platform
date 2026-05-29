from __future__ import annotations

import os
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_REQUEST_REFACTOR_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class RequestRefactorInput(BaseModel):
    plan_content: str = Field(..., description="Refactoring investigation details")


class RequestRefactorOutput(BaseModel):
    is_secure: bool = Field(..., description="True if refactoring plan is sufficient")
    missing_elements: List[str] = Field(default_factory=list, description="Missing safety guards or migration paths")
    status: str = Field(..., description="Status (PASSED, REJECTED_REQUEST_REFACTOR, WARN_REQUEST_REFACTOR)")


class PiRequestRefactorPlanVerifier:
    """Deterministic micro-agent that verifies refactoring plans for impact maps and rollback checks."""

    def __init__(self) -> None:
        self.agent_name = "PiRequestRefactorPlanVerifier"

    def verify_refactor(self, input_envelope: RequestRefactorInput) -> RequestRefactorOutput:
        plan = input_envelope.plan_content
        missing = []

        checks = [
            (["dependency", "impact", "dependencies"], "Missing impact analysis or dependency map"),
            (["migration", "deploy"], "Missing data, state migration, or deployment details"),
        ]

        for keys, desc in checks:
            if not any(k in plan.lower() for k in keys):
                missing.append(desc)

        is_secure = len(missing) == 0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_REQUEST_REFACTOR"
            else:
                status = "WARN_REQUEST_REFACTOR"
                is_secure = True

        return RequestRefactorOutput(is_secure=is_secure, missing_elements=missing, status=status)
