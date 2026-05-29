from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ORACLE_FALLBACK_STRICT_MODE")


class PriceFeedFallbackInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class PriceFeedFallbackOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if oracle price feed fallback checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityPriceFeedFallbackSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for oracle price feed fallback setups."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityPriceFeedFallbackSentry"

    def audit_price_feed_fallback(self, input_envelope: PriceFeedFallbackInput) -> PriceFeedFallbackOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions containing oracle calls, such as latestRoundData
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)", code)

        for name, _args, body in func_blocks:
            # Check if latestRoundData is called
            if "latestRoundData" in body or "getPrice" in body:
                # Scans if there is a secondary/fallback Oracle call or fallback TWAP logic or multi-feed fallback
                # Heuristic: look for fallback feed variables, secondary feed variables, or TWAP references
                # E.g. fallbackOracle, secondaryFeed, getTwap, twapPrice, or try/catch around oracle fetches
                has_fallback = False
                if any(x in body.lower() for x in ["fallback", "twap", "secondary", "catch", "backup", "pyth"]):
                    has_fallback = True

                if not has_fallback:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' reads from an external price feed oracle using 'latestRoundData' or 'getPrice' "
                        f"but does not implement a secondary/fallback pricing source (like TWAP or a backup oracle) in case "
                        f"the primary oracle suffers from an outage, lag, or zero-price freeze."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 70.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ORACLE_FALLBACK"
            else:
                status = "WARN_ORACLE_FALLBACK"
                is_secure = True

        return PriceFeedFallbackOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
