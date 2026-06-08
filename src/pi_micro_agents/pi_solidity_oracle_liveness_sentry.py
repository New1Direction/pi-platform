from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ORACLE_LIVENESS_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class OracleLivenessInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class OracleLivenessOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if oracle liveness validation checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed oracle liveness safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_ORACLE_LIVENESS, REJECTED_ORACLE_LIVENESS)"
    )


# 3. Core Micro-Agent Class
class PiSolidityOracleLivenessSentry:
    """Specialized Web3 micro-agent that audits price oracle integrations for stale price and liveness validation checks."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityOracleLivenessSentry"

    def audit_oracle_liveness(self, input_envelope: OracleLivenessInput) -> OracleLivenessOutput:
        """Autonomously audits Solidity contracts for correct latestRoundData freshness and answer validation checks."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            if "latestRoundData" in body:
                # Check if updatedAt is unpacked and checked for freshness
                # e.g., checking block.timestamp - updatedAt or checking if updatedAt == 0
                has_updated_at_unpack = re.search(r"\bupdatedAt\b", body)
                has_freshness_check = (
                    re.search(r"block\.timestamp\s*-\s*updatedAt", body)
                    or re.search(r"updatedAt\s*-\s*block\.timestamp", body)
                    or re.search(r"require\s*\(\s*updatedAt\s*>\s*0\s*\)", body)
                    or re.search(r"require\s*\(\s*updatedAt\s*!=\s*0\s*\)", body)
                )

                has_answer_validation = re.search(r"answer\s*>\s*0", body) or re.search(r"price\s*>\s*0", body)

                if not (has_updated_at_unpack and has_freshness_check and has_answer_validation):
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' queries an oracle via 'latestRoundData' but does not perform "
                        "adequate freshness validation. Ensure that 'updatedAt' is checked against a maximum "
                        "heartbeat threshold and the price answer is validated to be greater than zero to prevent stale oracle pricing exploits."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ORACLE_LIVENESS"
            else:
                status = "WARN_ORACLE_LIVENESS"
                is_secure = True

        return OracleLivenessOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
