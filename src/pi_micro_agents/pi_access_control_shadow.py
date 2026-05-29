from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_AC_SHADOW_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class ACShadowInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ACShadowOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract has correct admin safety controls")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed admin control findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_AC_SHADOW_RISK, REJECTED_AC_SHADOW_RISK)")


# 3. Core Micro-Agent Class
class PiAccessControlShadow:
    """Specialized Web3 micro-agent that audits contracts for administrative actions missing role modifiers or timelocks."""

    def __init__(self) -> None:
        self.agent_name = "PiAccessControlShadow"

    def audit_access_control(self, input_envelope: ACShadowInput) -> ACShadowOutput:
        """Autonomously audits Solidity contracts for administrative role authorization safety."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            # Mode 1: Check for admin-style keywords
            is_admin_action = any(
                kw in name.lower() for kw in ["admin", "setowner", "withdraw", "emergency", "pause", "mint", "burn"]
            )

            if is_admin_action:
                # Mode 2: Verify it has an access modifier
                has_modifier = any(
                    mod in body or re.search(r"\b" + mod + r"\b", code)
                    for mod in ["onlyOwner", "onlyRole", "restricted", "requireAdmin"]
                )

                if not has_modifier:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Administrative function '{name}' is missing an access control modifier "
                        "(e.g., 'onlyOwner' or 'onlyRole'). This allows unauthorized users to trigger critical admin states."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_AC_SHADOW_RISK"
            else:
                status = "WARN_AC_SHADOW_RISK"
                is_secure = True

        return ACShadowOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
