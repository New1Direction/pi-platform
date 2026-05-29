from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_READONLY_REENTRANCY_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_READONLY_REENTRANCY_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class ReadOnlyReentrancyInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")


class ReadOnlyReentrancyOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from read-only reentrancy risks")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed reentrancy and view-function safety findings"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_READONLY_REENTRANCY, REJECTED_READONLY_REENTRANCY)"
    )


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
class PiReadOnlyReentrancySentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for read-only reentrancy vulnerabilities and view-function safety."""

    def __init__(self) -> None:
        self.agent_name = "PiReadOnlyReentrancySentry"

    def audit_readonly_reentrancy(self, input_envelope: ReadOnlyReentrancyInput) -> ReadOnlyReentrancyOutput:
        """Autonomously audits Solidity contracts for read-only reentrancy risks."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        functions = extract_solidity_functions(code)

        for func_name, func_body, start_line in functions:
            # Clean comments
            cleaned_body = re.sub(r"//.*", "", func_body)
            cleaned_body = re.sub(r"/\*.*?\*/", "", cleaned_body, flags=re.DOTALL)

            # Mode 1: Read-Only Reentrancy Check
            # Look for calls querying external balances or prices on Curve/Balancer etc. (e.g. get_virtual_price, get_dy, balanceOf)
            if any(kw in cleaned_body for kw in ["get_virtual_price", "get_dy", "balanceOf"]):
                # Check if it has reentrancy protection on this view function or if it verifies pool lock
                # (e.g. check for require checks or lock methods like checkLock, nonReentrant)
                if not any(check in cleaned_body for check in ["nonReentrant", "checkLock", "require(", "assert("]):
                    vulnerable_funcs.append(func_name)
                    flagged_findings.append(
                        f"Function '{func_name}' on Line {start_line} queries external pool balances or pricing virtual functions "
                        f"without verifying if the external pool contract is currently locked/reentered. "
                        f"This exposes it to Read-Only Reentrancy exploits."
                    )

            # Mode 2: View-Function Safety Check
            # Check if view operations depend on transient or volatile states without assert boundaries
            if "view" in func_body or "pure" in func_body:
                if "block.timestamp" in cleaned_body and "require" not in cleaned_body:
                    flagged_findings.append(
                        f"Safety warning: View function '{func_name}' on Line {start_line} relies on block.timestamp "
                        f"for dynamic pricing query without validation checks."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_READONLY_REENTRANCY"
            else:
                status = "WARN_READONLY_REENTRANCY"
                is_secure = True

        return ReadOnlyReentrancyOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
