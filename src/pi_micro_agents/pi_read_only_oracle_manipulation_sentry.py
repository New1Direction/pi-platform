from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_READ_ONLY_ORACLE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_READ_ONLY_ORACLE_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class ReadOnlyOracleInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ReadOnlyOracleOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if price queries are secure against spot oracle manipulation")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed spot oracle manipulation findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_ORACLE_RISK, REJECTED_ORACLE_RISK)")


# 3. Core Micro-Agent Class
class PiReadOnlyOracleManipulationSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for read-only spot oracle price manipulation risks."""

    def __init__(self) -> None:
        self.agent_name = "PiReadOnlyOracleManipulationSentry"

    def audit_read_only_oracle(self, input_envelope: ReadOnlyOracleInput) -> ReadOnlyOracleOutput:
        """Autonomously audits Solidity contracts for spot balance queries lacking manipulation safety buffers."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            # Check if function queries spot pricing methods of Balancer, Curve, Uniswap reserves, etc.
            if ("getReserves" in body or "queryBatchSwap" in body or "get_dy" in body) and (
                "balanceOf" in body or "price" in name.lower() or "oracle" in name.lower()
            ):
                # Check if it lacks TWAP or secondary oracle verifications (Chainlink fallback)
                has_fallback = (
                    "latestRoundData" in body or "consult" in body or "observe" in body or "twap" in body.lower()
                )
                if not has_fallback:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' queries spot balance/swap rates directly from an AMM pool "
                        "without dynamic TWAP observations or Chainlink oracle verifications. This exposes "
                        "the contract to instant oracle price manipulation via flash loans."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ORACLE_RISK"
            else:
                status = "WARN_ORACLE_RISK"
                is_secure = True

        return ReadOnlyOracleOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
