from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_CIRCOM_UNDERCONSTRAINED_STRICT_MODE")


class CircomUnderconstrainedInput(BaseModel):
    file_path: str = Field(..., description="Circom source file path")
    circom_code: str = Field(..., description="Circom source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class CircomUnderconstrainedOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Circom underconstrained checks passed")
    vulnerable_signals: List[str] = Field(default_factory=list, description="Vulnerable signal names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiZKCircomUnderconstrainedSentry:
    """Specialized Web3 micro-agent that audits ZK Circom circuits to detect underconstrained signal assignments."""

    def __init__(self) -> None:
        self.agent_name = "PiZKCircomUnderconstrainedSentry"

    def audit_circom_constraints(self, input_envelope: CircomUnderconstrainedInput) -> CircomUnderconstrainedOutput:
        code = input_envelope.circom_code
        vulnerable_sigs = []
        flagged_findings = []

        # Find all templates in Circom
        templates = re.findall(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)\s*\{([\s\S]*?)(?=\ntemplate|\Z)", code)

        for name, _args, body in templates:
            # Find assignments without constraints, e.g. x <-- ... or ... --> x
            left_assigns = re.findall(r"([a-zA-Z0-9_]+)\s*<--", body)
            right_assigns = re.findall(r"-->\s*([a-zA-Z0-9_]+)", body)

            # Order-preserving dedup: iterating a set here made finding order depend
            # on PYTHONHASHSEED (nondeterministic output across processes).
            assigned_signals = list(dict.fromkeys(left_assigns + right_assigns))

            for sig in assigned_signals:
                # Check if this signal is constrained in the same body using ===
                constrained = False
                if re.search(rf"{sig}\s*===", body) or re.search(rf"===\s*{sig}", body):
                    constrained = True

                if not constrained:
                    vulnerable_sigs.append(sig)
                    flagged_findings.append(
                        f"Signal '{sig}' in template '{name}' is assigned using a non-constraining operator "
                        f"('<--' or '-->') but lacks a corresponding '===' constraint. This makes the circuit "
                        f"underconstrained, allowing potential proof forgery."
                    )

        is_secure = len(vulnerable_sigs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_CIRCOM_UNDERCONSTRAINED"
            else:
                status = "WARN_CIRCOM_UNDERCONSTRAINED"
                is_secure = True

        return CircomUnderconstrainedOutput(
            is_secure=is_secure,
            vulnerable_signals=vulnerable_sigs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
