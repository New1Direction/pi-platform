from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_MUTEX_SENTRY_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class MutexSentryInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class MutexSentryOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract mutex design is secure and gas-efficient")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed reentrancy mutex findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_MUTEX_RISK, REJECTED_MUTEX_RISK)")


# 3. Core Micro-Agent Class
class PiSolidityReentrancyMutexSentry:
    """Specialized Web3 micro-agent that audits contracts for custom boolean reentrancy mutex locks and gas inefficiencies."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityReentrancyMutexSentry"

    def audit_mutex(self, input_envelope: MutexSentryInput) -> MutexSentryOutput:
        """Autonomously audits Solidity contracts for secure, standard, and gas-efficient reentrancy locks."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find state variable declaration of custom boolean locks
        mutex_decl_match = re.search(r"\bbool\s+(private|public|internal)?\s*(locked|inSwap|reentrancyLock)\b", code)

        if mutex_decl_match:
            # Found custom rolled boolean reentrancy locks
            # Mode 1: Check if they toggle it manually using a boolean state variable
            # Booleans use expensive storage slots (20k gas to set to true, 5k to reset).
            manual_toggle_match = re.search(r"(locked|inSwap|reentrancyLock)\s*=\s*(true|false)", code)

            if manual_toggle_match:
                vulnerable_funcs.append("file_header")
                flagged_findings.append(
                    "Solidity contract declares a custom boolean reentrancy mutex: 'bool locked;'. "
                    "Custom boolean locks are expensive and highly prone to developer error (e.g. forgot to reset in fallback, "
                    "or missing try/catch safety). Use a standardized modifier 'nonReentrant' or modern transient storage instead."
                )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_MUTEX_RISK"
            else:
                status = "WARN_MUTEX_RISK"
                is_secure = True

        return MutexSentryOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
