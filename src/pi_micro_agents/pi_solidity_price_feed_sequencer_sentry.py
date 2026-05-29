from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SEQUENCER_LIVENESS_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_SEQUENCER_LIVENESS_STRICT_MODE", True))
        except Exception:
            pass
    return True


class PriceFeedSequencerInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class PriceFeedSequencerOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if L2 price feed sequencer checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityPriceFeedSequencerSentry:
    """Specialized Web3 micro-agent that audits Solidity code to ensure Chainlink Price Feeds validate the L2 Sequencer liveness."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityPriceFeedSequencerSentry"

    def audit_price_feed_sequencer(self, input_envelope: PriceFeedSequencerInput) -> PriceFeedSequencerOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions reading latestRoundData or price feeds
        func_blocks = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)', code)

        for name, args, body in func_blocks:
            if "latestRoundData" in body or "feed" in body.lower():
                # Check if sequencer liveness check is performed (checking variable containing 'sequencer')
                if not re.search(r'sequencer', body, re.IGNORECASE):
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' queries an oracle feed but does not perform a Sequencer Uptime Feed liveness check. "
                        f"On Layer-2 networks, this could lead to using stale/manipulated oracle prices during sequencer outages."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SEQUENCER_LIVENESS"
            else:
                status = "WARN_SEQUENCER_LIVENESS"
                is_secure = True

        return PriceFeedSequencerOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
