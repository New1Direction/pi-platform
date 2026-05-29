from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ZK_SIGNAL_UNCONSTRAINED_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class ZKSignalUnconstrainedInput(BaseModel):
    file_path: str = Field(..., description="Circom source file path")
    circom_code: str = Field(..., description="Circom source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ZKSignalUnconstrainedOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if all assigned signals have constraints")
    vulnerable_signals: List[str] = Field(default_factory=list, description="Vulnerable signal names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed findings on unconstrained assignments"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiZKSignalUnconstrainedConstraint:
    """Specialized ZK micro-agent that audits Circom templates for signals assigned via <-- or --> without active === constraints."""

    def __init__(self) -> None:
        self.agent_name = "PiZKSignalUnconstrainedConstraint"

    def audit_unconstrained_signals(self, input_envelope: ZKSignalUnconstrainedInput) -> ZKSignalUnconstrainedOutput:
        code = input_envelope.circom_code
        vulnerable_signals = []
        flagged_findings = []

        templates = re.findall(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for tname, _params, body in templates:
            # Find signals assigned via <-- or -->
            assignments = re.findall(r"([a-zA-Z0-9_]+)\s*(?:<--|-->)", body)
            for signal in assignments:
                # Check if there is a corresponding constraint (signal === or === signal)
                if not re.search(rf"{signal}\s*===", body) and not re.search(rf"===\s*{signal}", body):
                    vulnerable_signals.append(signal)
                    flagged_findings.append(
                        f"Template '{tname}': Signal '{signal}' is assigned values using non-constraining operators (<-- or -->) "
                        "but lacks a corresponding quadratic constraint (===). This allows a prover to supply arbitrary witness values."
                    )

        is_secure = len(vulnerable_signals) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ZK_SIGNAL_UNCONSTRAINED"
            else:
                status = "WARN_ZK_SIGNAL_UNCONSTRAINED"
                is_secure = True

        return ZKSignalUnconstrainedOutput(
            is_secure=is_secure,
            vulnerable_signals=vulnerable_signals,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
