from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_MATH_ROUNDING_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_MATH_ROUNDING_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class MathRoundingInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class MathRoundingOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract math uses correct rounding directions")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed math rounding findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_ROUNDING_RISK, REJECTED_ROUNDING_RISK)")


# 3. Core Micro-Agent Class
class PiDeFiMathRoundingSentry:
    """Specialized Web3 micro-agent that audits contracts for integer division rounding errors that favor the caller over the protocol."""

    def __init__(self) -> None:
        self.agent_name = "PiDeFiMathRoundingSentry"

    def audit_math_rounding(self, input_envelope: MathRoundingInput) -> MathRoundingOutput:
        """Autonomously audits Solidity math operations for division rounding direction safety."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        for name, args, body in func_blocks:
            # Mode 1: Check for share/asset conversion logic using integer division
            conversion_match = re.search(r'\b(convertToShares|convertToAssets|sharesToAssets|assetsToShares)\b', name)
            
            if conversion_match:
                # Mode 2: Verify if division is performed without dynamic rounding direction
                # Standard division in Solidity always rounds down. If converting shares to assets, it should round down.
                # However, if converting assets to shares (e.g. on deposit), rounding down favors the first depositor inflation attack.
                # In ERC-4626, convertToShares (on deposit/mint) should round down, convertToAssets (on withdraw/redeem) should round down.
                # But any custom dynamic math divisions that don't check for rounding safety should be flagged.
                unchecked_div_match = re.search(r'\/\s*[a-zA-Z0-9_]+', body)
                mul_div_up_missing = "mulDivUp" not in body and "Math.Rounding.Up" not in body

                if unchecked_div_match and mul_div_up_missing:
                    # Let's see if this is an asset-to-share dynamic conversion
                    if "deposit" in name.lower() or "mint" in name.lower() or "shares" in name.lower():
                        vulnerable_funcs.append(name)
                        flagged_findings.append(
                            f"Function '{name}' performs dynamic share or asset arithmetic division without "
                            "explicit rounding direction controls (e.g., missing OpenZeppelin Math rounding qualifiers). "
                            "Solidity division always rounds down. Rounding down on deposits/mints allows depositors "
                            "to exploit vault inflation math, leading to zero-value share minting."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ROUNDING_RISK"
            else:
                status = "WARN_ROUNDING_RISK"
                is_secure = True

        return MathRoundingOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
