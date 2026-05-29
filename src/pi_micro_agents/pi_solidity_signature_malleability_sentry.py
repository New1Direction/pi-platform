from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SIGNATURE_MALLEABILITY_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_SIGNATURE_MALLEABILITY_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class SignatureMalleabilityInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class SignatureMalleabilityOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if signature malleability checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed signature safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_MALLEABLE_SIG, REJECTED_MALLEABLE_SIG)")


# 3. Core Micro-Agent Class
class PiSoliditySignatureMalleabilitySentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for ecrecover ECDSA signature malleability vulnerabilities."""

    def __init__(self) -> None:
        self.agent_name = "PiSoliditySignatureMalleabilitySentry"

    def audit_signature_malleability(self, input_envelope: SignatureMalleabilityInput) -> SignatureMalleabilityOutput:
        """Autonomously audits Solidity contracts for signature malleability (ecrecover without s/v range checks)."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            # Check if ecrecover is used directly
            if "ecrecover" in body:
                # Check if it uses OpenZeppelin ECDSA library or checks for high s
                uses_safe_library = "ECDSA.recover" in body or "using ECDSA for" in code
                checks_s_value = (
                    "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0" in body
                    or "0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0" in body
                )

                if not (uses_safe_library or checks_s_value):
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' utilizes raw 'ecrecover' directly without validation for signature malleability. "
                        "Without checking that the 's' value is in the lower half range (<= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0), "
                        "an attacker can craft a malleable signature variant that bypasses replay checks."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_MALLEABLE_SIG"
            else:
                status = "WARN_MALLEABLE_SIG"
                is_secure = True

        return SignatureMalleabilityOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
