from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_DELEGATECALL_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_DELEGATECALL_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class DelegateCallInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")


class DelegateCallOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from unsafe delegatecalls")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed line and violation findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ...,
        description="Status classification (PASSED, WARN_DELEGATECALL_VULNERABILITY, REJECTED_DELEGATECALL_VULNERABILITY)",
    )


# 3. Helper function to extract concrete Solidity functions
def extract_solidity_functions(solidity_code: str) -> List[Tuple[str, str, int]]:
    functions = []
    code_len = len(solidity_code)

    # Pattern matching "function [name] (", "constructor (", "fallback (", or "receive ("
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

        # Calculate line number of start_idx
        start_line = solidity_code[:start_idx].count("\n") + 1

        # Semicolons and opening braces determine concrete vs abstract functions
        semicolon_idx = solidity_code.find(";", start_idx)
        brace_idx = solidity_code.find("{", start_idx)

        if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx):
            continue

        # Match braces to find full function block body
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


# 4. Core Micro-Agent Class
class PiDelegateCallGuard:
    """Specialized Web3 micro-agent that audits Solidity contracts for unsafe delegatecalls and EIP-1967 compliance."""

    def __init__(self) -> None:
        self.agent_name = "PiDelegateCallGuard"

    def audit_delegatecall(self, input_envelope: DelegateCallInput) -> DelegateCallOutput:
        """Autonomously audits Solidity contracts for delegatecall usage and proxy slot compliance."""
        code = input_envelope.solidity_code

        # Clean comments to avoid false positives in global analysis
        code_clean = re.sub(r"//.*", "", code)
        code_clean = re.sub(r"/\*.*?\*/", "", code_clean, flags=re.DOTALL)

        functions = extract_solidity_functions(code)

        vulnerable_funcs = []
        flagged_findings = []

        # Check globally if the standard EIP-1967 storage slot is referenced:
        # eip1967_slot = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
        has_eip1967_slot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" in code_clean.lower()

        for func_name, func_body, start_line in functions:
            if func_name == "constructor":
                continue

            # Clean comments for this function body
            cleaned_body = re.sub(r"//.*", "", func_body)
            cleaned_body = re.sub(r"/\*.*?\*/", "", cleaned_body, flags=re.DOTALL)

            # Check if delegatecall is used
            if "delegatecall(" in cleaned_body:
                # If EIP-1967 standard slot is present, we consider it a compliant Proxy delegation (Mode 2 compliance)
                if has_eip1967_slot:
                    continue

                # Otherwise, it might be an unsafe/arbitrary delegatecall (Mode 1 vulnerability)
                # Let's inspect the lines inside this function to pinpoint the delegatecall
                lines = cleaned_body.splitlines()
                for offset, line in enumerate(lines):
                    line_num = start_line + offset
                    stripped = line.strip()
                    if "delegatecall(" in stripped:
                        # Flag as vulnerable
                        if func_name not in vulnerable_funcs:
                            vulnerable_funcs.append(func_name)

                        flagged_findings.append(
                            f"Function '{func_name}' executes a delegatecall on Line {line_num}: '{stripped}' "
                            f"without references to the standard EIP-1967 storage slot "
                            f"(0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc), "
                            f"making it vulnerable to unauthorized delegatecall hijacks."
                        )
                        break

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_DELEGATECALL_VULNERABILITY"
            else:
                status = "WARN_DELEGATECALL_VULNERABILITY"
                is_secure = True  # Warn only in non-strict mode

        return DelegateCallOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
