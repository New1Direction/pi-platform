from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ZK_PROOF_FORGING_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class ZKProofForgingValidationInput(BaseModel):
    file_path: str = Field(..., description="Circom source file path")
    circom_code: str = Field(..., description="Circom source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ZKProofForgingValidationOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if proof verification steps guard against double-proof forging")
    vulnerable_signals: List[str] = Field(default_factory=list, description="Vulnerable methods or templates")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on proof forging checks")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiZKProofForgingValidationSentry:
    """Specialized ZK micro-agent that audits proof verifiers to ensure double-proof forging or proof replay is restricted."""

    def __init__(self) -> None:
        self.agent_name = "PiZKProofForgingValidationSentry"

    def audit_proof_forging(self, input_envelope: ZKProofForgingValidationInput) -> ZKProofForgingValidationOutput:
        code = input_envelope.circom_code
        vulnerable_signals = []
        flagged_findings = []

        templates = re.findall(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for tname, _params, body in templates:
            if "verify" in tname.lower() or "proof" in tname.lower():
                # Check if public inputs or signature parameters are verified against commitments
                if "commitment" not in body.lower() and "hash" not in body.lower() and "sha" not in body.lower():
                    vulnerable_signals.append(tname)
                    flagged_findings.append(
                        f"Verifier template '{tname}' does not associate proofs with unique commitment hashes. "
                        "Without checking a hash commitment of public parameters, attackers can forge or replay proofs across different contexts."
                    )

        is_secure = len(vulnerable_signals) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ZK_PROOF_FORGING"
            else:
                status = "WARN_ZK_PROOF_FORGING"
                is_secure = True

        return ZKProofForgingValidationOutput(
            is_secure=is_secure,
            vulnerable_signals=vulnerable_signals,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
