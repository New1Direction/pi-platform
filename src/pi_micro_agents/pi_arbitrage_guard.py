from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ARBITRAGE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_ARBITRAGE_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Static heuristic verification of arbitrage pool structures
def detect_arbitrage_anomalies(text: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0
    if not text:
        return 0.0, []

    # Heuristics for illegal routing or frontrun-vulnerable arbitrage patterns
    arbitrage_checks = [
        (r"\bno_slippage_protection\b", "disabled slippage checks found"),
        (r"0x0000000000000000000000000000000000000000", "zero address pool routing"),
        (r"gas_limit\s*[:=]\s*(9\d{6,})", "excessive gas limit setup representing resource exhaustion"),
    ]
    for pat, desc in arbitrage_checks:
        if re.search(pat, text, re.IGNORECASE):
            violations.append(desc)
            max_risk = max(max_risk, 90.0)

    return max_risk, violations


# 3. Pydantic-Enforced Input/Output Envelopes
class ArbitrageInput(BaseModel):
    token_in: str
    token_out: str
    amount_in: float
    pool_price_a: float
    pool_price_b: float
    min_spread_percent: float = Field(default=0.5, description="Minimum price gap to execute")


class ArbitrageOutput(BaseModel):
    should_execute: bool
    spread_detected_percent: float
    expected_profit: float
    target_wallet_type: str = "ERC-4337"
    route_details: str


# 4. Core Micro-Agent Class
class PiArbitrageGuard:
    """Autonomous routing guard managing EIP-4337 smart-contract wallet liquidity arbitrage."""

    def __init__(self) -> None:
        self.agent_name = "PiArbitrageGuard"

    def analyze_spread(self, input_envelope: ArbitrageInput) -> ArbitrageOutput:
        """Determines if a Web3 arbitrage opportunity is safe and profitable to route."""
        price_diff = abs(input_envelope.pool_price_a - input_envelope.pool_price_b)
        spread = (price_diff / min(input_envelope.pool_price_a, input_envelope.pool_price_b)) * 100.0

        expected_profit = 0.0
        should_execute = False
        route = "NO_PROFITABLE_ROUTE"

        if spread >= input_envelope.min_spread_percent:
            expected_profit = input_envelope.amount_in * (spread / 100.0)

            # Simple slippage/gas deduction: assume 0.1% transaction cost
            expected_profit -= input_envelope.amount_in * 0.001

            if expected_profit > 0.0:
                should_execute = True
                route = f"ROUTE_EXECUTION: Buy Pool A @ {input_envelope.pool_price_a}, Sell Pool B @ {input_envelope.pool_price_b}"

        # Safety Override Check (Strict Mode checks)
        is_strict = is_strict_mode()
        risk, violations = detect_arbitrage_anomalies(route)

        if is_strict and spread > 50.0:
            # Spreads over 50% usually represent oracle manipulation or flash loan hacks. Block execution.
            should_execute = False
            route = "BLOCKED_HIGH_RISK_SPREAD_ANOMALY (Oracle manipulation check triggered)"

        return ArbitrageOutput(
            should_execute=should_execute,
            spread_detected_percent=spread,
            expected_profit=expected_profit,
            route_details=route,
        )
