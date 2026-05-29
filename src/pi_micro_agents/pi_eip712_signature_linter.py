from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_EIP712_LINTER_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_EIP712_LINTER_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class EIP712LinterInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class EIP712LinterOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract conforms to EIP-712 structured signature standards")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed EIP-712 safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_EIP712_RISK, REJECTED_EIP712_RISK)")


# 3. Core Micro-Agent Class
class PiEIP712SignatureLinter:
    """Specialized Web3 micro-agent that audits Solidity contracts for EIP-712 signature verification flaws."""

    def __init__(self) -> None:
        self.agent_name = "PiEIP712SignatureLinter"

    def audit_signature_linter(self, input_envelope: EIP712LinterInput) -> EIP712LinterOutput:
        """Autonomously audits Solidity contracts for robust, secure EIP-712 domain separation setup."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        for name, args, body in func_blocks:
            # Check if function performs signature verification / ecrecover / ECDSA.recover
            if "ecrecover" in body or "recover" in body:
                # Check for dynamic domain separator inclusion (should contain block.chainid or similar dynamic elements)
                has_chainid = "chainid" in body or "DOMAIN_SEPARATOR" in body or "chainid" in code
                if not has_chainid:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' processes signature verification but does not appear to incorporate "
                        "block.chainid or a dynamic DOMAIN_SEPARATOR. This exposes signature validation to cross-chain replays."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_EIP712_RISK"
            else:
                status = "WARN_EIP712_RISK"
                is_secure = True

        return EIP712LinterOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
