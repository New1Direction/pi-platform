from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_PERMIT_GUARD_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_PERMIT_GUARD_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class PermitGuardInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class PermitGuardOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract has safe permit checks")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed permit signature safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_PERMIT_RISK, REJECTED_PERMIT_RISK)")


# 3. Core Micro-Agent Class
class PiERC20PermitPhishingGuard:
    """Specialized Web3 micro-agent that audits contracts for unvalidated permit parameters that enable phishing attacks."""

    def __init__(self) -> None:
        self.agent_name = "PiERC20PermitPhishingGuard"

    def audit_permit(self, input_envelope: PermitGuardInput) -> PermitGuardOutput:
        """Autonomously audits Solidity contracts for safe EIP-2612 / EIP-3009 gasless permit implementation patterns."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        for name, args, body in func_blocks:
            # Mode 1: Check for permit call integration
            permit_call_match = re.search(r'\.permit\s*\(', body)
            
            if permit_call_match:
                # Mode 2: Check if permit parameters use msg.sender instead of user-controlled signer variable
                # If they pass msg.sender as the owner of permit, then it is vulnerable to malicious signature replays
                sender_owner_match = re.search(r'\.permit\s*\(\s*msg\.sender\s*,', body)
                
                if not sender_owner_match:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' processes gasless signatures using '.permit()' with a "
                        "user-controlled owner parameter instead of locking it to 'msg.sender'. "
                        "This allows attackers to execute arbitrary signatures on behalf of other users, "
                        "posing severe approval phishing risks."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_PERMIT_RISK"
            else:
                status = "WARN_PERMIT_RISK"
                is_secure = True

        return PermitGuardOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
