from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_DOMAIN_SEPARATOR_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class DomainSeparatorInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class DomainSeparatorOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if DOMAIN_SEPARATOR checks passed")
    vulnerable_functions: List[str] = Field(
        default_factory=list, description="Vulnerable function names or variable declarations"
    )
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed domain separator safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_DOMAIN_SEPARATOR, REJECTED_DOMAIN_SEPARATOR)"
    )


# 3. Core Micro-Agent Class
class PiEIP712DomainSeparatorSentry:
    """Specialized Web3 micro-agent that audits upgradeable contracts for EIP-712 dynamic domain separator compliance."""

    def __init__(self) -> None:
        self.agent_name = "PiEIP712DomainSeparatorSentry"

    def audit_domain_separator(self, input_envelope: DomainSeparatorInput) -> DomainSeparatorOutput:
        """Autonomously audits Solidity upgradeable contracts for immutable or static domain separator initialization."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        is_upgradeable = "Initializable" in code or "UUPSUpgradeable" in code or "Upgradeable" in code

        if is_upgradeable:
            # Check if DOMAIN_SEPARATOR is declared immutable or constant
            has_immutable_separator = (
                re.search(r"bytes32\s+public\s+immutable\s+DOMAIN_SEPARATOR", code)
                or re.search(r"bytes32\s+public\s+constant\s+DOMAIN_SEPARATOR", code)
                or re.search(r"bytes32\s+immutable\s+DOMAIN_SEPARATOR", code)
            )

            # Check if DOMAIN_SEPARATOR is initialized inside the constructor instead of an initializer function or dynamically
            has_constructor_init = False
            constructor_match = re.search(r"constructor\s*\((.*?)\)\s*\{([\s\S]*?)\}", code)
            if constructor_match:
                constructor_body = constructor_match.group(2)
                if "DOMAIN_SEPARATOR" in constructor_body:
                    has_constructor_init = True

            if has_immutable_separator or has_constructor_init:
                vulnerable_funcs.append("DOMAIN_SEPARATOR")
                flagged_findings.append(
                    "The contract appears to be upgradeable but defines or initializes EIP-712 'DOMAIN_SEPARATOR' "
                    "as constant, immutable, or inside the constructor. In upgradeable proxies, this leads to incorrect "
                    "domain verification (using implementation address or outdated block.chainid), exposing the contract "
                    "to cross-chain signature replay attacks."
                )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_DOMAIN_SEPARATOR"
            else:
                status = "WARN_DOMAIN_SEPARATOR"
                is_secure = True

        return DomainSeparatorOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
