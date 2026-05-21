from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ZK_SIGNAL_SHADOWING_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class ZKSignalShadowingInput(BaseModel):
    file_path: str = Field(..., description="Circom source file path")
    circom_code: str = Field(..., description="Circom source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ZKSignalShadowingOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if signal shadowing or duplicate declarations are absent")
    vulnerable_signals: List[str] = Field(default_factory=list, description="Shadowed or duplicate signal names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on signal shadowing")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiZKSignalShadowingSignalSentry:
    """Specialized ZK micro-agent that audits Circom code for signal declarations that duplicate or shadow outer definitions."""

    def __init__(self) -> None:
        self.agent_name = "PiZKSignalShadowingSignalSentry"

    def audit_signal_shadowing(self, input_envelope: ZKSignalShadowingInput) -> ZKSignalShadowingOutput:
        code = input_envelope.circom_code
        vulnerable_signals = []
        flagged_findings = []

        templates = re.findall(r'template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        for tname, params, body in templates:
            # Find all signals declared, e.g. signal input x, signal output y, signal z
            declarations = re.findall(r'signal\s+(?:input|output)?\s*([a-zA-Z0-9_]+)', body)
            seen_signals = set()
            for sig in declarations:
                if sig in seen_signals:
                    vulnerable_signals.append(sig)
                    flagged_findings.append(
                        f"Template '{tname}': Signal '{sig}' is declared more than once, leading to potential variable shadowing and constraint bypassing."
                    )
                seen_signals.add(sig)

        is_secure = len(vulnerable_signals) == 0
        risk_score = 65.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ZK_SIGNAL_SHADOWING"
            else:
                status = "WARN_ZK_SIGNAL_SHADOWING"
                is_secure = True

        return ZKSignalShadowingOutput(
            is_secure=is_secure,
            vulnerable_signals=vulnerable_signals,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
