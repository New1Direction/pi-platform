from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_REENTRANCY_GUARD_OVERLAP_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class ReentrancyGuardOverlapInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ReentrancyGuardOverlapOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if there are no overlapping reentrancy guards")
    vulnerable_functions: List[str] = Field(
        default_factory=list, description="Functions with nested or overlapping guards"
    )
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on overlapping guards")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityReentrancyGuardOverlapSentry:
    """Specialized Web3 micro-agent that audits contracts for overlapping or redundant reentrancy guard modifiers."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityReentrancyGuardOverlapSentry"

    def audit_reentrancy_overlap(self, input_envelope: ReentrancyGuardOverlapInput) -> ReentrancyGuardOverlapOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find function declarations and modifiers
        func_matches = re.finditer(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)([^{]*)\{", code)

        for match in func_matches:
            func_name = match.group(1)
            attributes = match.group(3)

            # Check if there are multiple reentrancy-like modifiers
            reentrancy_keywords = ["nonReentrant", "noReentrancy", "lock", "mutex", "prevReentrant"]
            found_keywords = [kw for kw in reentrancy_keywords if re.search(r"\b" + kw + r"\b", attributes)]

            if len(found_keywords) > 1:
                vulnerable_funcs.append(func_name)
                flagged_findings.append(
                    f"Function '{func_name}' has overlapping/redundant reentrancy guards: {found_keywords}. "
                    "This creates redundant state updates, increases gas consumption, and risks deadlocks or unexpected execution failures."
                )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 65.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_REENTRANCY_GUARD_OVERLAP"
            else:
                status = "WARN_REENTRANCY_GUARD_OVERLAP"
                is_secure = True

        return ReentrancyGuardOverlapOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
