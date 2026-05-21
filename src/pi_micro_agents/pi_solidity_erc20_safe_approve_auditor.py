from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ERC20_SAFE_APPROVE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class ERC20SafeApproveInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ERC20SafeApproveOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract approve patterns are secure")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on unsafe approve usage")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityERC20SafeApproveAuditor:
    """Specialized Web3 micro-agent that audits Solidity contracts for deprecated or unsafe direct ERC20 approve() patterns."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityERC20SafeApproveAuditor"

    def audit_safe_approve(self, input_envelope: ERC20SafeApproveInput) -> ERC20SafeApproveOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        for name, args, body in func_blocks:
            # Check for direct .approve call, e.g. token.approve(spender, amount)
            # Safe methods are safeApprove, safeIncreaseAllowance, etc.
            direct_approves = re.findall(r'\b([a-zA-Z0-9_]+\.approve\s*\(.*?\))', body)
            
            for call in direct_approves:
                # Flag if it doesn't utilize safeApprove
                vulnerable_funcs.append(name)
                flagged_findings.append(
                    f"Function '{name}' calls direct external ERC20 approve method '{call}' instead of SafeERC20 'safeApprove'. "
                    "Some tokens (like USDT) do not return a boolean value or have dynamic behavior, causing direct approve calls to fail silently or lock up allowance configurations."
                )
                break

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ERC20_SAFE_APPROVE"
            else:
                status = "WARN_ERC20_SAFE_APPROVE"
                is_secure = True

        return ERC20SafeApproveOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
