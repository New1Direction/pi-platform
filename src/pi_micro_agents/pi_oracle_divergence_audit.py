from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ORACLE_DIV_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class OracleDivergenceInput(BaseModel):
    file_path: str = Field(..., description="Pricing aggregator or contract file path")
    prices: List[float] = Field(..., description="Observed price feed values")
    benchmarks: List[float] = Field(..., description="Benchmark (e.g. Chainlink reference) values")
    max_deviation_percent: float = Field(default=2.0, description="Maximum permitted deviation percent")
    solidity_code: str = Field(default="", description="Solidity code of pricing aggregator (optional)")


class OracleDivergenceOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if price deviation is within safe limits and math is correct")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names or assets")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed deviation and formulation findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_ORACLE_DIVERGENCE, REJECTED_ORACLE_DIVERGENCE)"
    )


# 3. Core Micro-Agent Class
class PiOracleDivergenceAudit:
    """Specialized Web3 micro-agent that audits price oracle inputs for excessive divergence and incorrect aggregation math."""

    def __init__(self) -> None:
        self.agent_name = "PiOracleDivergenceAudit"

    def audit_divergence(self, input_envelope: OracleDivergenceInput) -> OracleDivergenceOutput:
        """Autonomously audits price feeds for divergence and correct geometric/harmonic aggregation formulations."""
        prices = input_envelope.prices
        benchmarks = input_envelope.benchmarks
        max_dev = input_envelope.max_deviation_percent
        code = input_envelope.solidity_code

        vulnerable_funcs = []
        flagged_findings = []

        # Mode 1: Oracle Manipulation Scan (Price array comparison)
        min_len = min(len(prices), len(benchmarks))
        for i in range(min_len):
            p = prices[i]
            b = benchmarks[i]
            if b <= 0.0:
                continue
            dev = abs(p - b) / b * 100.0
            if dev > max_dev:
                vulnerable_funcs.append(f"asset_feed_{i}")
                flagged_findings.append(
                    f"Oracle price deviation at index {i} is {dev:.2f}%, exceeding max deviation limit of {max_dev:.2f}% "
                    f"(Price: {p}, Benchmark: {b}). Potential price manipulation threat detected."
                )

        # Mode 2: Aggregation Math Check (Solidity pattern scan)
        if code:
            code_lower = code.lower()
            # Clean comments
            code_clean = re.sub(r"//.*", "", code_lower)
            code_clean = re.sub(r"/\*.*?\*/", "", code_clean, flags=re.DOTALL)

            # Look for simple average patterns (addition divided by count) which can be manipulated in illiquid pools
            if "sum" in code_clean and "/" in code_clean and "length" in code_clean:
                # Recommend geometric/harmonic mean aggregation for AMM prices
                if not any(kw in code_clean for kw in ["geometric", "harmonic", "sqrt", "log"]):
                    flagged_findings.append(
                        "Aggregation formulation warning: Pricing aggregator appears to calculate simple arithmetic average. "
                        "Using simple arithmetic averages of AMM spot prices makes it highly susceptible to flash loan manipulation. "
                        "Recommend implementing geometric or harmonic mean aggregation (e.g. Uniswap V3 TWAP)."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ORACLE_DIVERGENCE"
            else:
                status = "WARN_ORACLE_DIVERGENCE"
                is_secure = True

        return OracleDivergenceOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
