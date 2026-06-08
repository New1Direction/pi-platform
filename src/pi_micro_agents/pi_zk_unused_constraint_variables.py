from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ZK_UNUSED_CONSTRAINT_STRICT_MODE")


class ZKUnusedConstraintInput(BaseModel):
    file_path: str = Field(..., description="Circom source file path")
    circom_code: str = Field(..., description="Circom source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ZKUnusedConstraintOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if all defined constraint variables are active in assertions")
    vulnerable_signals: List[str] = Field(default_factory=list, description="Unused signal or variable names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed findings on unused constraint variables"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiZKUnusedConstraintVariables:
    """Specialized ZK micro-agent that audits Circom circuits for defined signals/variables completely omitted from constraints."""

    def __init__(self) -> None:
        self.agent_name = "PiZKUnusedConstraintVariables"

    def audit_unused_variables(self, input_envelope: ZKUnusedConstraintInput) -> ZKUnusedConstraintOutput:
        code = input_envelope.circom_code
        vulnerable_signals = []
        flagged_findings = []

        templates = re.findall(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for tname, _params, body in templates:
            # Find all signals declared
            declarations = re.findall(r"signal\s+(?:input|output)?\s*([a-zA-Z0-9_]+)", body)
            # Find all statements containing a constraint operator (<==, ==>, ===)
            constraint_statements = [
                stmt for stmt in body.split(";") if any(op in stmt for op in ["<==", "==>", "==="])
            ]
            for sig in declarations:
                # Check if the signal is used in at least one constraint statement as a word
                is_used = False
                for stmt in constraint_statements:
                    if re.search(rf"\b{sig}\b", stmt):
                        is_used = True
                        break
                if not is_used:
                    vulnerable_signals.append(sig)
                    flagged_findings.append(
                        f"Template '{tname}': Declared signal '{sig}' is never bound or used in any constraint equations (<==, ==>, ===). "
                        "Unconstrained signals let attackers manipulate inputs without altering the proof validation flow."
                    )

        is_secure = len(vulnerable_signals) == 0
        risk_score = 70.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ZK_UNUSED_CONSTRAINT"
            else:
                status = "WARN_ZK_UNUSED_CONSTRAINT"
                is_secure = True

        return ZKUnusedConstraintOutput(
            is_secure=is_secure,
            vulnerable_signals=vulnerable_signals,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
