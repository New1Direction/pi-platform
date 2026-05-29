from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_EXTERNAL_CONTRACTS_RETURN_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class ExternalContractsReturnInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ExternalContractsReturnOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract external call returns are checked")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed findings on external contract call returns"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityExternalContractsReturnCheck:
    """Specialized Web3 micro-agent that audits contracts to ensure that low-level call(), delegatecall(), or staticcall() returns are verified."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityExternalContractsReturnCheck"

    def audit_external_returns(self, input_envelope: ExternalContractsReturnInput) -> ExternalContractsReturnOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            # Check for low level calls: .call, .delegatecall, .staticcall
            calls = re.findall(r"(\b[a-zA-Z0-9_]+\.(?:call|delegatecall|staticcall)\b\s*\(.*?\))", body)
            for call in calls:
                # A safe call should capture its return value: e.g. (bool success, ) = ...
                # Let's check if the call line stores the result in a variable
                # Find the full statement containing the call
                statement_match = re.search(r"([^;]*?" + re.escape(call) + r"[^;]*);", body)
                if statement_match:
                    statement = statement_match.group(1)
                    # Check if 'success' or '=' is present before the call
                    has_assignment = "=" in statement and any(
                        var in statement.split("=")[0] for var in ["success", "ok", "result", "status", "res"]
                    )
                    # Check if it's asserted: require(success) or if (success)
                    has_check = has_assignment and any(kw in body for kw in ["require", "assert", "if", "revert"])

                    if not has_check:
                        vulnerable_funcs.append(name)
                        flagged_findings.append(
                            f"Function '{name}' executes low-level external call '{call}' but does not explicitly check its return value. "
                            "Unchecked call returns can cause transactions to fail silently or let attackers exploit failed execution states."
                        )
                        break  # flag the function once

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_EXTERNAL_CONTRACTS_RETURN"
            else:
                status = "WARN_EXTERNAL_CONTRACTS_RETURN"
                is_secure = True

        return ExternalContractsReturnOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
