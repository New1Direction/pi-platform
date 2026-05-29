from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_REENTRANCY_SPEC_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_REENTRANCY_SPEC_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class ReentrancyGuardSpecInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ReentrancyGuardSpecOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract conforms to reentrancy safety standards")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed reentrancy safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_REENTRANCY_RISK, REJECTED_REENTRANCY_RISK)"
    )


# 3. Core Micro-Agent Class
class PiReentrancyGuardSpec:
    """Specialized Web3 micro-agent that audits Solidity contracts for custom/incorrect reentrancy protections and CEI violations."""

    def __init__(self) -> None:
        self.agent_name = "PiReentrancyGuardSpec"

    def audit_reentrancy_spec(self, input_envelope: ReentrancyGuardSpecInput) -> ReentrancyGuardSpecOutput:
        """Autonomously audits Solidity contracts for state modification ordering and missing ReentrancyGuard patterns."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            # Mode 1: Check for external call before state write
            external_call_match = re.search(r"\.(call|transfer|send)\s*\(", body)
            state_write_match = re.search(r"([a-zA-Z0-9_]+)\s*(\+=|-=|=)\s*", body)

            if external_call_match and state_write_match:
                # Find positions to see if state write happens after external call
                call_pos = body.find(external_call_match.group(0))
                write_pos = body.find(state_write_match.group(0))

                if write_pos > call_pos:
                    # Check if it has a nonReentrant modifier
                    has_modifier = "nonReentrant" in code or re.search(r"\bnonReentrant\b", body)
                    if not has_modifier:
                        vulnerable_funcs.append(name)
                        flagged_findings.append(
                            f"Function '{name}' performs an external call before a state-changing operation "
                            "and is missing the 'nonReentrant' modifier. This violates the Checks-Effects-Interactions (CEI) pattern."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_REENTRANCY_RISK"
            else:
                status = "WARN_REENTRANCY_RISK"
                is_secure = True

        return ReentrancyGuardSpecOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
