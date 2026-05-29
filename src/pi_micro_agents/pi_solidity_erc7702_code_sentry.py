from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ERC7702_CODE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_ERC7702_CODE_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class ERC7702CodeInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ERC7702CodeOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if ERC-7702 code checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed ERC-7702 delegation target findings"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_ERC7702_CODE, REJECTED_ERC7702_CODE)")


# 3. Core Micro-Agent Class
class PiSolidityERC7702CodeSentry:
    """Specialized Web3 micro-agent that audits EIP-7702 delegation targets to prevent self-destruct and mutability exploits."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityERC7702CodeSentry"

    def audit_erc7702_code(self, input_envelope: ERC7702CodeInput) -> ERC7702CodeOutput:
        """Autonomously audits Solidity contracts for safe EIP-7702 delegation targets and parameter checking."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, args, body in func_blocks:
            # Check if function appears to handle EIP-7702 delegation target setup
            if "delegate" in args or "delegation" in body or "authorized" in body:
                # Look for a parameter named delegate or target or delegateCode
                param_matches = re.findall(
                    r"address\s+([a-zA-Z0-9_]*delegate[a-zA-Z0-9_]*|[a-zA-Z0-9_]*target[a-zA-Z0-9_]*)",
                    args,
                    re.IGNORECASE,
                )
                if param_matches:
                    for param in param_matches:
                        # Check if it verifies target contract bytecode or whitelist
                        # e.g., checking if it has a whitelist or checks for selfdestruct code size or extcodesize
                        has_whitelist_check = re.search(r"whitelist|isWhitelisted|allowed|trusted", body, re.IGNORECASE)
                        has_destruct_validation = (
                            "extcodesize" in body or "code.length" in body or "extcodehash" in body
                        )

                        if not (has_whitelist_check or has_destruct_validation):
                            vulnerable_funcs.append(name)
                            flagged_findings.append(
                                f"Function '{name}' accepts a delegation target parameter '{param}' "
                                "but fails to perform security validation. Unvalidated EIP-7702 delegation targets "
                                "could point to contracts containing self-destruct opcodes or mutable states, "
                                "which can lead to permanent compromise of the delegating EOA account."
                            )
                            break

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ERC7702_CODE"
            else:
                status = "WARN_ERC7702_CODE"
                is_secure = True

        return ERC7702CodeOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
