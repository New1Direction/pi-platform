from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SELFDESTRUCT_CODE_ERASE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class SelfdestructCodeEraseInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class SelfdestructCodeEraseOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is secure from selfdestruct risks")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on selfdestruct usage")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSoliditySelfdestructCodeEraseSentry:
    """Specialized Web3 micro-agent that audits contracts to detect risky or deprecated selfdestruct/suicide invocations in dynamic upgrades."""

    def __init__(self) -> None:
        self.agent_name = "PiSoliditySelfdestructCodeEraseSentry"

    def audit_selfdestruct_usage(self, input_envelope: SelfdestructCodeEraseInput) -> SelfdestructCodeEraseOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            # Check for selfdestruct or suicide
            if "selfdestruct" in body or "suicide" in body:
                vulnerable_funcs.append(name)
                flagged_findings.append(
                    f"Function '{name}' contains 'selfdestruct' or 'suicide' operation. "
                    "Under Cancun EVM specifications (EIP-6780), selfdestruct will only erase the contract's code/state "
                    "if executed in the same transaction it was deployed. Otherwise, it only sends ether, leaving the bytecode intact, risking locked funds or upgrade path breakage."
                )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SELFDESTRUCT_CODE_ERASE"
            else:
                status = "WARN_SELFDESTRUCT_CODE_ERASE"
                is_secure = True

        return SelfdestructCodeEraseOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
