from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_CONSTANT_PRAGMA_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class ConstantPragmaInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ConstantPragmaOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract compiler version is locked")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on floating pragma version usage")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityConstantPragmaValidation:
    """Specialized Web3 micro-agent that audits Solidity contracts for floating compiler version pragmas (e.g. ^0.8.0, >=0.8.0)."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityConstantPragmaValidation"

    def audit_constant_pragma(self, input_envelope: ConstantPragmaInput) -> ConstantPragmaOutput:
        code = input_envelope.solidity_code
        flagged_findings = []

        # Find pragma statement
        pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', code)

        if pragma_match:
            version_expr = pragma_match.group(1).strip()
            # Floating characters: ^, >, <, >=, <=
            is_floating = any(char in version_expr for char in ["^", ">", "<"])
            
            if is_floating:
                flagged_findings.append(
                    f"Solidity file utilizes floating pragma compiler definition 'pragma solidity {version_expr};'. "
                    "Production contracts should lock the compiler version to a specific release (e.g., 0.8.20) "
                    "to prevent accidental compilation under untested versions containing unknown optimizer bugs or compiler defects."
                )

        is_secure = len(flagged_findings) == 0
        risk_score = 50.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_CONSTANT_PRAGMA"
            else:
                status = "WARN_CONSTANT_PRAGMA"
                is_secure = True

        return ConstantPragmaOutput(
            is_secure=is_secure,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
