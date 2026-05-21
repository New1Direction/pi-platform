from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_TIMESTAMP_INTERVAL_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_TIMESTAMP_INTERVAL_STRICT_MODE", True))
        except Exception:
            pass
    return True


class TimestampIntervalInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class TimestampIntervalOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if timestamp interval checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityBlockTimestampIntervalSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for safe block.timestamp interval boundaries in distribution functions."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityBlockTimestampIntervalSentry"

    def audit_timestamp_interval(self, input_envelope: TimestampIntervalInput) -> TimestampIntervalOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Target functions commonly doing timestamp-based distribution, staking, or vesting
        func_blocks = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)', code)

        for name, args, body in func_blocks:
            # Check if block.timestamp is referenced
            if "block.timestamp" in body:
                # If there's block.timestamp arithmetic but no require/assert/if condition verifying a time gap
                # E.g. lastUpdate + interval <= block.timestamp or block.timestamp >= lastUpdate + interval
                # Let's search for an interval checking pattern
                has_interval_validation = False
                if re.search(r'(block\.timestamp\s*(>=|>)\s*[a-zA-Z0-9_]+\s*\+\s*[a-zA-Z0-9_]+)', body):
                    has_interval_validation = True
                if re.search(r'([a-zA-Z0-9_]+\s*\+\s*[a-zA-Z0-9_]+\s*(<=|<)\s*block\.timestamp)', body):
                    has_interval_validation = True
                if re.search(r'(block\.timestamp\s*-\s*[a-zA-Z0-9_]+\s*(>=|>)\s*[a-zA-Z0-9_]+)', body):
                    has_interval_validation = True

                # Staking, vesting, or distribution functions must validate interval spacing
                if any(x in name.lower() for x in ["stake", "vest", "distribute", "claim", "reward", "withdraw"]):
                    if not has_interval_validation:
                        vulnerable_funcs.append(name)
                        flagged_findings.append(
                            f"Function '{name}' references 'block.timestamp' in a staking, reward, or vesting context "
                            f"but lacks structural time-interval threshold checks (e.g. require(block.timestamp >= lastClaim + INTERVAL)). "
                            f"This can allow premature claims or trigger mathematical distribution inconsistencies."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 65.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_TIMESTAMP_INTERVAL"
            else:
                status = "WARN_TIMESTAMP_INTERVAL"
                is_secure = True

        return TimestampIntervalOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
