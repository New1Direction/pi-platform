from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_MEV_SHIELD_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_MEV_SHIELD_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class MEVShieldInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class MEVShieldOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract AMM trades are safe from MEV slippage risks")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed MEV sandwich findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_MEV_RISK, REJECTED_MEV_RISK)")


# 3. Core Micro-Agent Class
class PiSandwichMEVShield:
    """Specialized Web3 micro-agent that audits contracts for AMM slippage configurations prone to sandwich attacks."""

    def __init__(self) -> None:
        self.agent_name = "PiSandwichMEVShield"

    def audit_mev_shield(self, input_envelope: MEVShieldInput) -> MEVShieldOutput:
        """Autonomously audits Solidity contracts for proper slippage parameters and swap limit protections."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        for name, args, body in func_blocks:
            # Mode 1: Check for swap operations
            swap_match = re.search(r'\b(swapExactTokensForTokens|swapTokensForExactTokens|exactInput|exactOutput|swap)\b', body)
            
            if swap_match:
                # Mode 2: Verify if amountOutMin is hardcoded to 0
                zero_slippage_match = re.search(r'amountOutMin\s*=\s*0|minAmountOut\s*=\s*0|amountOutMinimum\s*=\s*0', body)
                hardcoded_swap_zero = re.search(r'\bswapExactTokensForTokens\s*\(\s*[^,]+,\s*0\s*,', body)

                if zero_slippage_match or hardcoded_swap_zero:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' executes a token swap with a hardcoded minimum output of 0. "
                        "This permits execution under infinite slippage, exposing the trade to complete "
                        "frontrunning / sandwich MEV theft."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_MEV_RISK"
            else:
                status = "WARN_MEV_RISK"
                is_secure = True

        return MEVShieldOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
