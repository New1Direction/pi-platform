from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_OWNER_TIMELOCK_STRICT_MODE")


class OwnerTimelockInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class OwnerTimelockOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract administrative actions have timelocks")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on missing timelocks")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityOwnerTimelockSentry:
    """Specialized Web3 micro-agent that audits contracts to ensure that administrative onlyOwner or onlyRole privilege functions are protected by timelocks."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityOwnerTimelockSentry"

    def audit_owner_timelock(self, input_envelope: OwnerTimelockInput) -> OwnerTimelockOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Check if contract mentions timelock or delay in any variable/function/comment
        has_timelock_mechanism = any(
            kw in code.lower() for kw in ["timelock", "delay", "min_delay", "queuedtransactions"]
        )

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, _body in func_blocks:
            # Check if this function is onlyOwner or restricted
            is_admin_action = "onlyOwner" in code and re.search(
                r"\bfunction\s+" + name + r"\s*\(.*?\)[^{]*?\bonlyOwner\b", code
            )

            if is_admin_action and not has_timelock_mechanism:
                # Extra check: excludes standard view or configuration functions that are low risk
                is_low_risk = any(kw in name.lower() for kw in ["get", "view", "is", "renounce"])
                if not is_low_risk:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Administrative function '{name}' has 'onlyOwner' modifier but the contract lacks a timelock mechanism. "
                        "Without a timelock, compromised admin keys can immediately drain funds or alter critical parameters without giving users time to withdraw."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 65.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_OWNER_TIMELOCK"
            else:
                status = "WARN_OWNER_TIMELOCK"
                is_secure = True

        return OwnerTimelockOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
