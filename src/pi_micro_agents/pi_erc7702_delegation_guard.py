from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ERC7702_GUARD_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_ERC7702_GUARD_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class ERC7702Input(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ERC7702Output(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is secure against ERC-7702 delegation exploits")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed ERC-7702 delegation safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_ERC7702_RISK, REJECTED_ERC7702_RISK)")


# 3. Core Micro-Agent Class
class PiERC7702DelegationGuard:
    """Specialized Web3 micro-agent that audits contracts for ERC-7702 EOA delegation signature & authorization safety."""

    def __init__(self) -> None:
        self.agent_name = "PiERC7702DelegationGuard"

    def audit_erc7702_delegation(self, input_envelope: ERC7702Input) -> ERC7702Output:
        """Autonomously audits Solidity delegation controls for ERC-7702 compliance and security."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        for name, args, body in func_blocks:
            # Check for delegation hooks, authorization setups, or signature checks in EOA context
            if "delegate" in name.lower() or "authorize" in name.lower() or "signature" in body.lower():
                # EIP-7702 dynamic checks should ensure that signatures are not static and include nonces to prevent replay
                if "nonce" not in body.lower() and "nonces" not in code.lower() and "ecrecover" in body:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' processes dynamic account delegation/signatures but does not implement "
                        "nonce tracking. This exposes the EIP-7702 smart account delegation to message replay attacks."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ERC7702_RISK"
            else:
                status = "WARN_ERC7702_RISK"
                is_secure = True

        return ERC7702Output(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
