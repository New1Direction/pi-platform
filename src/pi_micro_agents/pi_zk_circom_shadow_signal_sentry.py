from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_CIRCOM_SHADOW_SIGNAL_STRICT_MODE", True))
        except Exception:
            pass
    return True


class CircomShadowSignalInput(BaseModel):
    file_path: str = Field(..., description="Circom source file path")
    circom_code: str = Field(..., description="Circom source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class CircomShadowSignalOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Circom shadow signal checks passed")
    vulnerable_signals: List[str] = Field(default_factory=list, description="Vulnerable signal names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiZKCircomShadowSignalSentry:
    """Specialized Web3 micro-agent that audits ZK Circom templates to detect local variables/signals shadowing parameters or input signals."""

    def __init__(self) -> None:
        self.agent_name = "PiZKCircomShadowSignalSentry"

    def audit_shadow_signals(self, input_envelope: CircomShadowSignalInput) -> CircomShadowSignalOutput:
        code = input_envelope.circom_code
        vulnerable_sigs = []
        flagged_findings = []

        # Find all templates in Circom
        templates = re.findall(r"template\s+([a-zA-Z0-9_]+)\s*\((.*?)\)\s*\{([\s\S]*?)(?=\ntemplate|\Z)", code)

        for name, args, body in templates:
            # Parse template parameters
            params = [p.strip() for p in args.split(",") if p.strip()]

            # Find input and output signal declarations in the template body
            signals = re.findall(r"signal\s+(input|output)?\s*([a-zA-Z0-9_]+)", body)
            defined_signals = [sig[1] for sig in signals]

            # Look for local variable declarations: var var_name; or var var_name = ...;
            var_declarations = re.findall(r"var\s+([a-zA-Z0-9_]+)", body)

            # Look for duplicate definitions / shadowing
            for var_name in var_declarations:
                # Check if it shadows a parameter or a signal
                shadowed = False
                shadow_type = ""
                if var_name in params:
                    shadowed = True
                    shadow_type = "template parameter"
                elif var_name in defined_signals:
                    shadowed = True
                    shadow_type = "signal declaration"

                if shadowed:
                    vulnerable_sigs.append(var_name)
                    flagged_findings.append(
                        f"Variable '{var_name}' in template '{name}' shadows an existing {shadow_type}. "
                        f"Shadowing signal or parameter names inside ZK circuits can lead to incorrect "
                        f"constraint mapping, signal collisons, and underconstrained proving systems."
                    )

        is_secure = len(vulnerable_sigs) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_CIRCOM_SHADOW_SIGNAL"
            else:
                status = "WARN_CIRCOM_SHADOW_SIGNAL"
                is_secure = True

        return CircomShadowSignalOutput(
            is_secure=is_secure,
            vulnerable_signals=vulnerable_sigs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
