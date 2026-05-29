from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_AA_SENTRY_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_AA_SENTRY_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class AccountAbstractionInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class AccountAbstractionOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract conforms to ERC-4337 specifications")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed ERC-4337 validation findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_AA_RISK, REJECTED_AA_RISK)")


# 3. Core Micro-Agent Class
class PiEIP4337AccountAbstractionSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for ERC-4337 Smart Account/Paymaster validation issues."""

    def __init__(self) -> None:
        self.agent_name = "PiEIP4337AccountAbstractionSentry"

    def audit_account_abstraction(self, input_envelope: AccountAbstractionInput) -> AccountAbstractionOutput:
        """Autonomously audits Solidity Smart Accounts/Paymasters for bundler constraints."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            # Check for paymaster or account abstraction validation methods: validateUserOp, validatePaymasterUserOp
            if "validateUserOp" in name or "validatePaymasterUserOp" in name:
                # ERC-4337 bans accessing global block metadata, blockhash, gasleft, tx.origin, timestamp, number etc.
                forbidden_patterns = [
                    (r"\btx\.origin\b", "tx.origin"),
                    (r"\bblock\.blockhash\b", "block.blockhash"),
                    (r"\bblock\.timestamp\b", "block.timestamp"),
                    (r"\bblock\.number\b", "block.number"),
                    (r"\bgasleft\s*\(", "gasleft()"),
                ]
                for pattern, keyword in forbidden_patterns:
                    if re.search(pattern, body):
                        vulnerable_funcs.append(name)
                        flagged_findings.append(
                            f"Validation function '{name}' accesses forbidden global state parameter '{keyword}'. "
                            "This violates ERC-4337 bundler simulation restrictions, causing transaction rejection."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_AA_RISK"
            else:
                status = "WARN_AA_RISK"
                is_secure = True

        return AccountAbstractionOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
