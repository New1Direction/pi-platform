from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_INITIALIZABLE_GAP_STRICT_MODE")


class InitializableGapInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class InitializableGapOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if upgradeable contracts have proper storage gaps")
    vulnerable_contracts: List[str] = Field(default_factory=list, description="Vulnerable contract names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on missing storage gaps")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityInitializableGapSentry:
    """Specialized Web3 micro-agent that audits upgradeable contracts (proxies) for missing storage gaps (e.g., uint256[50] __gap)."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityInitializableGapSentry"

    def audit_initializable_gap(self, input_envelope: InitializableGapInput) -> InitializableGapOutput:
        code = input_envelope.solidity_code
        vulnerable_contracts = []
        flagged_findings = []

        # Find all contracts
        contracts = re.findall(r"contract\s+([a-zA-Z0-9_]+)(?:\s+is\s+([a-zA-Z0-9_,\s]+))?\s*\{([\s\S]*?)\}", code)

        for name, inheritance, body in contracts:
            # Check if this is an upgradeable or base parent contract
            # Upgradeable contracts typically inherit from Initializable, or end in 'Upgradeable', or are abstract
            is_upgradeable = "Upgradeable" in name or "Initializable" in inheritance or "abstract" in code

            if is_upgradeable:
                # Check for standard storage gap variable: e.g. uint256[50] __gap or similar
                has_gap = re.search(r"uint256\s*\[\s*\d+\s*\]\s*(?:private|internal)?\s*__gap\s*;", body)
                if not has_gap:
                    vulnerable_contracts.append(name)
                    flagged_findings.append(
                        f"Upgradeable parent contract '{name}' is missing a storage gap (__gap variable). "
                        "Without a storage gap, adding new state variables to this base contract in future upgrades will shift storage layout slots in derived contracts, causing silent state corruption."
                    )

        is_secure = len(vulnerable_contracts) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_INITIALIZABLE_GAP"
            else:
                status = "WARN_INITIALIZABLE_GAP"
                is_secure = True

        return InitializableGapOutput(
            is_secure=is_secure,
            vulnerable_contracts=vulnerable_contracts,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
