from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_TX_ORIGIN_CALL_CHECK_STRICT_MODE")


class TxOriginCallCheckInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class TxOriginCallCheckOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract tx.origin checks are secure")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on tx.origin check usage")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityTxOriginCallCheckSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for vulnerable tx.origin authentication checks, especially in fallback/receive handlers."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityTxOriginCallCheckSentry"

    def audit_tx_origin_call(self, input_envelope: TxOriginCallCheckInput) -> TxOriginCallCheckOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions including fallback and receive
        func_blocks = re.findall(
            r"(function\s+[a-zA-Z0-9_]+\s*\(.*?\)|fallback\s*\(.*?\)|receive\s*\(.*?\))[^{]*\{([\s\S]*?)\}", code
        )

        for decl, body in func_blocks:
            # Check if tx.origin is used for authorization
            if "tx.origin" in body and ("require" in body or "assert" in body or "if" in body):
                name = decl.strip()
                vulnerable_funcs.append(name)
                flagged_findings.append(
                    f"Handler '{name}' utilizes 'tx.origin' for verification or authorization checks. "
                    "Using tx.origin for authentication makes the contract vulnerable to phishing attacks (swapping identity of callers via intermediate malicious contracts)."
                )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_TX_ORIGIN_CALL_CHECK"
            else:
                status = "WARN_TX_ORIGIN_CALL_CHECK"
                is_secure = True

        return TxOriginCallCheckOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
