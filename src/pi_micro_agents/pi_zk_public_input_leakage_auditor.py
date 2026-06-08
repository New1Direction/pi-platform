from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ZK_PUBLIC_INPUT_LEAKAGE_STRICT_MODE")


class ZKPublicInputLeakageInput(BaseModel):
    file_path: str = Field(..., description="Circom source file path")
    circom_code: str = Field(..., description="Circom source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ZKPublicInputLeakageOutput(BaseModel):
    is_secure: bool = Field(
        ..., description="Indicates if there is no leakage of private witnesses into public parameters"
    )
    vulnerable_signals: List[str] = Field(default_factory=list, description="Leaked or exposed signal names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on public leakage")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiZKPublicInputLeakageAuditor:
    """Specialized ZK micro-agent that audits Circom templates for leakage of private inputs into public fields or commitments."""

    def __init__(self) -> None:
        self.agent_name = "PiZKPublicInputLeakageAuditor"

    def audit_public_input_leakage(self, input_envelope: ZKPublicInputLeakageInput) -> ZKPublicInputLeakageOutput:
        code = input_envelope.circom_code
        vulnerable_signals = []
        flagged_findings = []

        templates = re.findall(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for tname, params, body in templates:
            # Find public/private specifications in main component or standard markers
            if "public" in params or "public" in body:
                # Scans if private signals or secret parameters are exposed via direct assignment to a public signal
                # Matches patterns where a signal identified with 'secret' or 'priv' is assigned to an 'out' or 'pub' signal
                assignments = re.findall(
                    r"([a-zA-Z0-9_]*pub[a-zA-Z0-9_]*|[a-zA-Z0-9_]*out[a-zA-Z0-9_]*)\s*(?:<==|<--|=)\s*([a-zA-Z0-9_]*secret[a-zA-Z0-9_]*|[a-zA-Z0-9_]*priv[a-zA-Z0-9_]*)",
                    body,
                    re.IGNORECASE,
                )
                for public_sig, private_sig in assignments:
                    vulnerable_signals.append(private_sig)
                    flagged_findings.append(
                        f"Template '{tname}': Leakage detected where private witness '{private_sig}' is assigned to public signal '{public_sig}'. "
                        "Exposing private inputs in public components completely undermines zero-knowledge privacy properties."
                    )

        is_secure = len(vulnerable_signals) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ZK_PUBLIC_INPUT_LEAKAGE"
            else:
                status = "WARN_ZK_PUBLIC_INPUT_LEAKAGE"
                is_secure = True

        return ZKPublicInputLeakageOutput(
            is_secure=is_secure,
            vulnerable_signals=vulnerable_signals,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
