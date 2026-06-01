from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ZK_NON_PRIME_FIELD_STRICT_MODE")


class ZKNonPrimeFieldRangeInput(BaseModel):
    file_path: str = Field(..., description="Circom source file path")
    circom_code: str = Field(..., description="Circom source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ZKNonPrimeFieldRangeOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if signal ranges do not exceed prime field boundaries")
    vulnerable_signals: List[str] = Field(default_factory=list, description="Vulnerable signal or parameter names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed findings on prime field range errors"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiZKNonPrimeFieldRangeSentry:
    """Specialized ZK micro-agent that audits signal bounds checking against the circuit's prime field capacity."""

    def __init__(self) -> None:
        self.agent_name = "PiZKNonPrimeFieldRangeSentry"

    def audit_non_prime_range(self, input_envelope: ZKNonPrimeFieldRangeInput) -> ZKNonPrimeFieldRangeOutput:
        code = input_envelope.circom_code
        vulnerable_signals = []
        flagged_findings = []

        # Find large integer constants that might exceed or equal standard BN254 / BLS12-381 primes
        # BN254 prime (r) is roughly 21888242871839275222246405745257275088548364400416034343698204186575808495617
        bn254_prime = 21888242871839275222246405745257275088548364400416034343698204186575808495617

        # Look for literal numbers in code
        literals = re.findall(r"\b([0-9]{10,})\b", code)
        for lit in literals:
            val = int(lit)
            if val >= bn254_prime:
                vulnerable_signals.append(lit)
                flagged_findings.append(
                    f"Constant literal '{lit}' exceeds or equals the standard BN254 ZK scalar field prime order. "
                    "Performing checks or constraints using elements outside the prime field boundary causes modular wrap-around, defeating range constraints."
                )

        is_secure = len(vulnerable_signals) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ZK_NON_PRIME_FIELD"
            else:
                status = "WARN_ZK_NON_PRIME_FIELD"
                is_secure = True

        return ZKNonPrimeFieldRangeOutput(
            is_secure=is_secure,
            vulnerable_signals=vulnerable_signals,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
