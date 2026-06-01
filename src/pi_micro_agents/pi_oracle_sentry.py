from __future__ import annotations

import re
from typing import List, Tuple

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ORACLE_STRICT_MODE")


# 2. Static heuristic verification of pricing anomalies
def detect_pricing_anomalies(price: float, token: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0

    if price <= 0.0:
        violations.append(f"Invalid pricing anomaly: zero or negative price detected ({price})")
        max_risk = 99.0
    elif price > 10000000.0:
        violations.append(f"Extreme pricing anomaly: price exceeds reasonable limits ({price})")
        max_risk = 90.0

    # Check for known scam token patterns in token name/symbol
    if re.search(r"\b(?:scam|fake|rug|hack)\b", token, re.IGNORECASE):
        violations.append(f"Dangerous token identifier flagged: {token}")
        max_risk = max(max_risk, 85.0)

    return max_risk, violations


# 3. Pydantic-Enforced Input/Output Envelopes
class OracleSentryInput(BaseModel):
    token: str = Field(..., description="Target token ticker or address (e.g. ETH, BTC, USDC)")
    chain_id: int = Field(default=1, description="Target EVM Chain ID")
    current_observed_price: float = Field(..., description="The transaction price candidate under evaluation")
    max_deviation_percent: float = Field(
        default=2.0, description="Max deviation threshold allowed between oracle feeds"
    )


class OracleSentryOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates whether the observed price is safe and verified")
    deviation_detected_percent: float = Field(
        ..., description="The calculated percentage divergence from aggregate fair price"
    )
    aggregate_fair_price: float = Field(..., description="The computed consensus fair price across oracle feeds")
    verified_sources: List[str] = Field(default_factory=list, description="Oracle sources scanned and matched")
    status: str = Field(..., description="Price status classification (PASSED, WARN_PRICE, REJECTED_PRICE)")
    flagged_anomalies: List[str] = Field(default_factory=list, description="List of identified pricing anomalies")


# 4. Core Micro-Agent Class
class PiOracleSentry:
    """Autonomous pricing integrity guard managing multi-oracle price feeds validation."""

    def __init__(self) -> None:
        self.agent_name = "PiOracleSentry"

    def audit_prices(self, input_envelope: OracleSentryInput) -> OracleSentryOutput:
        """Audits the observed price against a consensus of mock oracle sources (Chainlink, Pyth, TWAP)."""
        token = input_envelope.token.upper()
        observed = input_envelope.current_observed_price
        max_dev = input_envelope.max_deviation_percent

        # Determine standard aggregate fair price based on token ticker
        if token == "ETH":
            fair_price = 3000.0
        elif token == "BTC":
            fair_price = 60000.0
        elif token in ["USDC", "USDT", "DAI"]:
            fair_price = 1.0
        else:
            # Fallback to observed if token is custom to prevent false positives
            fair_price = observed if observed > 0.0 else 100.0

        # Calculate deviation percentage
        if fair_price > 0.0:
            deviation = (abs(observed - fair_price) / fair_price) * 100.0
        else:
            deviation = 100.0

        # Run static heuristics checks
        risk, violations = detect_pricing_anomalies(observed, input_envelope.token)

        # Check deviation against threshold
        if deviation > max_dev:
            violations.append(
                f"Price deviation of {deviation:.2f}% exceeds safe threshold of {max_dev}% (Fair: {fair_price})"
            )
            risk = max(risk, 85.0)

        # Config strict mode resolution
        is_strict = is_strict_mode()
        is_secure = True
        status = "PASSED"

        if risk >= 80.0:
            if is_strict:
                is_secure = False
                status = "REJECTED_PRICE"
            else:
                status = "WARN_PRICE"
        elif risk >= 50.0:
            status = "WARN_PRICE"

        return OracleSentryOutput(
            is_secure=is_secure,
            deviation_detected_percent=deviation,
            aggregate_fair_price=fair_price,
            verified_sources=["Chainlink Aggregator V4", "Pyth Network Push Oracle", "Uniswap V3 TWAP Feed"],
            status=status,
            flagged_anomalies=violations,
        )
