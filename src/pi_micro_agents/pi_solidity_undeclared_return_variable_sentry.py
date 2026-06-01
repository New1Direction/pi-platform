from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_UNDECLARED_RETURN_VARIABLE_STRICT_MODE")


class UndeclaredReturnVariableInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class UndeclaredReturnVariableOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract returns are secure and properly assigned")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed findings on unassigned return slots"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityUndeclaredReturnVariableSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for return variables declared in function signatures but never explicitly assigned or returned."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityUndeclaredReturnVariableSentry"

    def audit_undeclared_returns(self, input_envelope: UndeclaredReturnVariableInput) -> UndeclaredReturnVariableOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions with named return variables
        # e.g., function getVal() public returns (uint256 value) { ... }
        # Match: function name ( args ) ... returns ( ... [var_name] ) { body }
        func_matches = re.finditer(
            r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*?returns\s*\((.*?)\)\s*\{([\s\S]*?)\}", code
        )

        for match in func_matches:
            name = match.group(1)
            returns_clause = match.group(3)
            body = match.group(4)

            # Check if there is a named return variable (e.g. "uint256 value" or "address admin")
            # Splitting by comma to handle multiple returns
            slots = returns_clause.split(",")
            for slot in slots:
                parts = slot.strip().split()
                if len(parts) >= 2:
                    # The last part is likely the variable name (e.g. "value" in "uint256 value")
                    var_name = parts[-1].strip()
                    # Exclude keywords like memory, storage, calldata
                    if var_name not in ["memory", "storage", "calldata", "payable"]:
                        # Check if var_name is assigned anywhere in the body, or if there is a return statement containing var_name
                        is_assigned = re.search(r"\b" + re.escape(var_name) + r"\b\s*[-+=\/]?=", body)
                        is_returned = re.search(r"\breturn\b\s+[^;]*?\b" + re.escape(var_name) + r"\b", body)

                        if not is_assigned and not is_returned:
                            vulnerable_funcs.append(name)
                            flagged_findings.append(
                                f"Function '{name}' declares a named return slot '{var_name}' but never assigns or explicitly returns it. "
                                "This will cause the function to return a default/zero value, which might trigger severe logic flaws or incorrect status results."
                            )
                            break  # flag this function once

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_UNDECLARED_RETURN_VARIABLE"
            else:
                status = "WARN_UNDECLARED_RETURN_VARIABLE"
                is_secure = True

        return UndeclaredReturnVariableOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
