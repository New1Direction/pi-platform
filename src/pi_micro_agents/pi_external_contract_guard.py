from __future__ import annotations

import re
from typing import List, Tuple

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
# is_strict_mode is now provided by pi_micro_agents.utils
# kept as a local shim for backward compatibility
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_EXTERNAL_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class ExternalContractGuardInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ExternalContractGuardOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from obvious unsafe external call risks")
    vulnerable_functions: List[str] = Field(
        default_factory=list, description="Vulnerable function names or variable names"
    )
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed external contract safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_EXTERNAL_RISK, REJECTED_EXTERNAL_RISK)")


# Helper to extract functions
def extract_solidity_functions(solidity_code: str) -> List[Tuple[str, str, int]]:
    functions = []
    code_len = len(solidity_code)

    pattern = re.compile(r"\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(")

    for match in pattern.finditer(solidity_code):
        keyword = match.group(1)
        name = match.group(2)
        if keyword == "function":
            func_name = name
        elif keyword == "constructor":
            func_name = "constructor"
        elif keyword == "fallback":
            func_name = "fallback"
        else:
            func_name = "receive"

        start_idx = match.start()
        start_line = solidity_code[:start_idx].count("\n") + 1

        semicolon_idx = solidity_code.find(";", start_idx)
        brace_idx = solidity_code.find("{", start_idx)

        if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx):
            continue

        brace_count = 1
        curr_idx = brace_idx + 1
        while curr_idx < code_len and brace_count > 0:
            char = solidity_code[curr_idx]
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
            curr_idx += 1

        if brace_count == 0:
            func_body = solidity_code[start_idx:curr_idx]
            functions.append((func_name, func_body, start_line))

    return functions


# 3. Core Micro-Agent Class
class PiExternalContractGuard:
    """Specialized Web3 micro-agent that audits Solidity contracts for untrusted external contract calls and interface mismatches."""

    def __init__(self) -> None:
        self.agent_name = "PiExternalContractGuard"

    def audit_external(self, input_envelope: ExternalContractGuardInput) -> ExternalContractGuardOutput:
        """Autonomously audits Solidity contracts for external contract call risks and interface declarations."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        functions = extract_solidity_functions(code)

        # Clean comments
        code_clean = re.sub(r"//.*", "", code)
        code_clean = re.sub(r"/\*.*?\*/", "", code_clean, flags=re.DOTALL)

        for func_name, func_body, start_line in functions:
            cleaned_body = re.sub(r"//.*", "", func_body)
            cleaned_body = re.sub(r"/\*.*?\*/", "", cleaned_body, flags=re.DOTALL)

            # Mode 1: Untrusted External Contract call checking
            # Identify setting of external addresses (e.g. constructor or setter function taking address parameter)
            # Flag if parameter is assigned to state variable without address(0) validation check
            address_param_match = re.search(
                r"\bfunction\b\s+([a-zA-Z0-9_]+)\s*\(\s*address\s+([a-zA-Z0-9_]+)\b", func_body
            )
            if address_param_match:
                setter_func = address_param_match.group(1)
                param_name = address_param_match.group(2)
                # Check if param is set without "address(0)" or "0x" require validation
                if re.search(r"\b" + re.escape(param_name) + r"\s*=\s*[a-zA-Z0-9_]+", cleaned_body):
                    if not any(check in cleaned_body for check in ["address(0)", "0x0"]):
                        vulnerable_funcs.append(setter_func)
                        flagged_findings.append(
                            f"Function '{setter_func}' on Line {start_line} accepts external address parameter '{param_name}' "
                            f"and assigns it without checking if it is address(0), risking silent bricking or logic failures."
                        )

            # Mode 2: Interface Match check
            # Verify if calling standard IERC transfer/transferFrom but missing signature compliance return checks
            if "transfer(" in cleaned_body or "transferfrom(" in cleaned_body:
                # Standard interface requires checking return values or using safeTransfer
                if not any(safe in cleaned_body.lower() for safe in ["safetransfer", "require(", "assert("]):
                    flagged_findings.append(
                        f"Interface Warning: Function '{func_name}' on Line {start_line} performs a raw ERC-20 transfer "
                        f"or transferFrom call without wrapping it in SafeERC20 or verifying its return value boolean."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_EXTERNAL_RISK"
            else:
                status = "WARN_EXTERNAL_RISK"
                is_secure = True

        return ExternalContractGuardOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
