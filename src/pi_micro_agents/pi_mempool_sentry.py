from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_MEMPOOL_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_MEMPOOL_STRICT_MODE", True))
        except Exception:
            pass
    return True

# 2. Static heuristic scanning of mempool raw transactions
def detect_mempool_exploits(text: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0
    if not text:
        return 0.0, []

    # Heuristics for malicious MEV, sandwich, or frontrunning keywords/calldata
    frontrun_patterns = [
        (r"\bfrontrun\b", "frontrun signature found"),
        (r"\bsandwich_attack\b", "sandwich attack signature found"),
        (r"0x5f5755ce", "Uniswap swapExactTokensForTokens transaction match"),
        (r"flash_loan|flashloan", "flash loan routing block found"),
    ]
    for pat, desc in frontrun_patterns:
        if re.search(pat, text, re.IGNORECASE):
            violations.append(desc)
            max_risk = max(max_risk, 85.0)

    # Detect sandwich slippage parameter triggers (unsafe high slippage limits)
    if "slippage" in text.lower():
        slippage_match = re.search(r"slippage\s*[:=]\s*(\d+(\.\d+)?)", text, re.IGNORECASE)
        if slippage_match:
            val = float(slippage_match.group(1))
            if val > 5.0: # high slippage limit > 5% represents sandwich vulnerability
                violations.append(f"excessive slippage configuration '{val}%' flagged")
                max_risk = max(max_risk, 90.0)

    return max_risk, violations

# 3. Pydantic-Enforced Input/Output Envelopes
class MempoolTxInput(BaseModel):
    transaction_hash: str
    calldata: str
    gas_price_gwei: float
    value_eth: float = 0.0
    slippage_limit: float = Field(default=0.5, description="Slippage percentage cap")

class MempoolTxOutput(BaseModel):
    is_admitted: bool
    risk_score: float
    status: str
    alerts: List[str] = Field(default_factory=list)

# 4. Core Micro-Agent Class
class PiMempoolSentry:
    """Stateless transaction interceptor that acts as Layer 4 Mempool gate."""

    def __init__(self) -> None:
        self.agent_name = "PiMempoolSentry"

    def check_transaction(self, input_envelope: MempoolTxInput) -> MempoolTxOutput:
        """Evaluates pending transaction calldata and gas profiles to block frontrunning/MEV exploits."""
        risk, violations = detect_mempool_exploits(input_envelope.calldata)

        # Check gas price spike anomalies (> 500 Gwei represents extreme gas-war frontrunning)
        if input_envelope.gas_price_gwei > 500.0:
            violations.append(f"gas price spike detected ({input_envelope.gas_price_gwei} Gwei)")
            risk = max(risk, 80.0)

        # Check slippage limit violations
        if input_envelope.slippage_limit > 5.0:
            violations.append(f"slippage limit too high ({input_envelope.slippage_limit}%)")
            risk = max(risk, 75.0)

        is_strict = is_strict_mode()
        is_admitted = True
        status = "PASSED"

        if risk >= 80.0:
            if is_strict:
                is_admitted = False
                status = "REJECTED_EXPLOIT"
            else:
                status = "WARN_EXPLOIT"

        return MempoolTxOutput(
            is_admitted=is_admitted,
            risk_score=risk,
            status=status,
            alerts=violations
        )
