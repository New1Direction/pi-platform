from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_CIRCOM_DIVISION_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class ZKCircomDivisionInput(BaseModel):
    file_path: str = Field(..., description="Circom source file path")
    circom_code: str = Field(..., description="Circom source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ZKCircomDivisionOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Circom division checks passed")
    vulnerable_signals: List[str] = Field(default_factory=list, description="Vulnerable signal names or variables")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed Circom zero-division findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_CIRCOM_DIVISION, REJECTED_CIRCOM_DIVISION)"
    )


# 3. Core Micro-Agent Class
class PiZKCircomDivisionSentry:
    """Specialized ZK micro-agent that audits Circom circuits for under-constrained division and division-by-zero vulnerabilities."""

    def __init__(self) -> None:
        self.agent_name = "PiZKCircomDivisionSentry"

    def audit_circom_division(self, input_envelope: ZKCircomDivisionInput) -> ZKCircomDivisionOutput:
        """Autonomously audits Circom code for division constraints without non-zero checks on divisors."""
        code = input_envelope.circom_code
        vulnerable_signals = []
        flagged_findings = []

        # Find templates
        templates = re.findall(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for tname, _params, body in templates:
            # Find any division statement, e.g. a <-- b / c or similar
            div_matches = re.finditer(
                r"([a-zA-Z0-9_]+)\s*(?:<--|-->|=)\s*([a-zA-Z0-9_]+)\s*(?:/|\\)\s*([a-zA-Z0-9_]+)", body
            )
            for match in div_matches:
                dest = match.group(1)
                match.group(2)
                divisor = match.group(3)

                # Check if divisor is constrained to be non-zero (e.g. divisor === 0 or divisor !== 0 or assert(divisor != 0))
                # Or checks if there is a constraint checking divisor is non-zero
                is_constrained = (
                    re.search(rf"\b{divisor}\s*!==?\s*0", body)
                    or re.search(rf"assert\s*\(\s*{divisor}\s*!=?\s*0\s*\)", body)
                    or re.search(rf"{divisor}\s*===\s*0", body)
                )  # checked for zero block handling

                if not is_constrained:
                    vulnerable_signals.append(divisor)
                    flagged_findings.append(
                        f"Template '{tname}' performs division using divisor '{divisor}' "
                        f"to assign signal '{dest}', but does not explicitly constrain '{divisor}' to be non-zero. "
                        "This may lead to division-by-zero execution panic or under-constrained malicious inputs during proof generation."
                    )

        is_secure = len(vulnerable_signals) == 0
        risk_score = 70.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_CIRCOM_DIVISION"
            else:
                status = "WARN_CIRCOM_DIVISION"
                is_secure = True

        return ZKCircomDivisionOutput(
            is_secure=is_secure,
            vulnerable_signals=vulnerable_signals,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
