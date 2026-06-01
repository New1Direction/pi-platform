from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ZK_CIRCUIT_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class ZKCircuitInput(BaseModel):
    file_path: str = Field(..., description="Circom ZK source file path")
    circom_code: str = Field(..., description="Circom source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ZKCircuitOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Circom template is secure against under-constrained signals")
    vulnerable_signals: List[str] = Field(default_factory=list, description="Vulnerable signal names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed ZK circuit under-constraint findings"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_ZK_RISK, REJECTED_ZK_RISK)")


# 3. Core Micro-Agent Class
class PiZeroKnowledgeCircuitSentry:
    """Specialized Web3 micro-agent that audits ZK Circom templates for under-constrained signals."""

    def __init__(self) -> None:
        self.agent_name = "PiZeroKnowledgeCircuitSentry"

    def audit_zk_circuit(self, input_envelope: ZKCircuitInput) -> ZKCircuitOutput:
        """Autonomously audits Circom code for signal under-constraints (assignments without matching constraints)."""
        code = input_envelope.circom_code
        vulnerable_signals = []
        flagged_findings = []

        # Find templates in Circom
        templates = re.findall(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for tname, _targs, tbody in templates:
            # Look for signal declarations: e.g. signal input in; signal output out;
            re.findall(r"signal\s+(?:input|output|private)?\s*([a-zA-Z0-9_]+)\s*;", tbody)

            # Check if there is an unconstrained assignment (<-- or -->)
            assignments = re.findall(r"([a-zA-Z0-9_]+)\s*(?:<--|-->)\s*", tbody)

            for sig in assignments:
                # If sig is assigned with <-- or -->, verify if there is a corresponding constraint assertion with ===
                # Specifically checking if 'sig ===' or '=== sig' appears in the body
                constraint_pattern = r"(\b" + sig + r"\b\s*===|===\s*\b" + sig + r"\b)"
                if not re.search(constraint_pattern, tbody):
                    if sig not in vulnerable_signals:
                        vulnerable_signals.append(sig)
                        flagged_findings.append(
                            f"Signal '{sig}' in template '{tname}' is assigned using an unconstrained operator "
                            "(<-- or -->) but lacks a matching dynamic constraint assertion (===). "
                            "This creates an under-constrained circuit, allowing malicious witnesses to bypass rules."
                        )

        is_secure = len(vulnerable_signals) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ZK_RISK"
            else:
                status = "WARN_ZK_RISK"
                is_secure = True

        return ZKCircuitOutput(
            is_secure=is_secure,
            vulnerable_signals=vulnerable_signals,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
