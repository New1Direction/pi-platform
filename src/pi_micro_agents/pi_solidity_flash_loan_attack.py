from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_SOLIDITY_FLASH_LOAN_STRICT_MODE")


class SolidityFlashLoanInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class SolidityFlashLoanOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if flash loan checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityFlashLoanAttack:
    """Specialized DeFi micro-agent that audits Solidity contracts for vulnerable flash loan integration patterns."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityFlashLoanAttack"

    def audit_flash_loan(self, input_envelope: SolidityFlashLoanInput) -> SolidityFlashLoanOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions doing flashloan-related callbacks
        # E.g. executeOperation, flashLoan, receiveFlashLoan
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)", code)

        for name, args, body in func_blocks:
            if any(x in name.lower() for x in ["executeoperation", "flashloan", "receiveflashloan"]):
                # Look for calls to pool state modifications or swaps without explicit validation of sender
                # E.g. lacks require(msg.sender == pool) or modifier checks
                has_sender_verification = False
                if re.search(r"(msg\.sender\s*==\s*[a-zA-Z0-9_]+)", body):
                    has_sender_verification = True
                if "onlyPool" in args or "onlyLendingPool" in args or "onlyPool" in body or "onlyLendingPool" in body:
                    has_sender_verification = True

                if not has_sender_verification:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Flash loan callback function '{name}' is implemented but lacks structural "
                        f"verification of the caller ('msg.sender'). An attacker could call this callback directly "
                        f"to manipulate internal storage structures or drain contract reserves."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_FLASH_LOAN"
            else:
                status = "WARN_FLASH_LOAN"
                is_secure = True

        return SolidityFlashLoanOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
