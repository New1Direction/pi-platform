from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_UNIV3_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_UNIV3_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class UniV3SentryInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class UniV3SentryOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Uniswap V3 interaction has adequate oracle controls")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed Uniswap V3 safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_UNIV3_RISK, REJECTED_UNIV3_RISK)")


# 3. Core Micro-Agent Class
class PiUniswapV3PoolSentry:
    """Specialized Web3 micro-agent that audits contracts for slot0 price manipulation vulnerabilities without TWAP protection."""

    def __init__(self) -> None:
        self.agent_name = "PiUniswapV3PoolSentry"

    def audit_uniswap_v3(self, input_envelope: UniV3SentryInput) -> UniV3SentryOutput:
        """Autonomously audits Solidity contracts for correct Uniswap V3 TWAP/slot0 price usage patterns."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        for name, args, body in func_blocks:
            # Mode 1: Check for direct slot0 queries
            slot0_match = re.search(r'\.slot0\s*\(', body)
            observe_match = re.search(r'\.observe\s*\(', body)

            if slot0_match and not observe_match:
                vulnerable_funcs.append(name)
                flagged_findings.append(
                    f"Function '{name}' calls '.slot0()' directly to determine token prices/ratios "
                    "without using a decentralized Oracle TWAP fallback '.observe()'. This exposes the "
                    "contract to catastrophic spot price manipulation attacks."
                )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_UNIV3_RISK"
            else:
                status = "WARN_UNIV3_RISK"
                is_secure = True

        return UniV3SentryOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
