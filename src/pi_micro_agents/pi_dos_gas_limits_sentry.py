from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_DOS_GAS_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_DOS_GAS_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class DoSGasLimitsInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class DoSGasLimitsOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from block gas limit DoS risks")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed DoS gas limits findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_DOS_GAS_RISK, REJECTED_DOS_GAS_RISK)")


# Helper to extract functions
def extract_solidity_functions(solidity_code: str) -> List[Tuple[str, str, int]]:
    functions = []
    code_len = len(solidity_code)

    pattern = re.compile(r'\b(function|constructor|fallback|receive)\b\s*([a-zA-Z0-9_]*)\s*\(')

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
        start_line = solidity_code[:start_idx].count('\n') + 1

        semicolon_idx = solidity_code.find(';', start_idx)
        brace_idx = solidity_code.find('{', start_idx)

        if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx):
            continue

        brace_count = 1
        curr_idx = brace_idx + 1
        while curr_idx < code_len and brace_count > 0:
            char = solidity_code[curr_idx]
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
            curr_idx += 1

        if brace_count == 0:
            func_body = solidity_code[start_idx:curr_idx]
            functions.append((func_name, func_body, start_line))

    return functions


# 3. Core Micro-Agent Class
class PiDoSGasLimitsSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for DoS via Block Gas Limits and enforces Pull-over-Push payment patterns."""

    def __init__(self) -> None:
        self.agent_name = "PiDoSGasLimitsSentry"

    def audit_dos_gas(self, input_envelope: DoSGasLimitsInput) -> DoSGasLimitsOutput:
        """Autonomously audits Solidity contracts for external calls in loops and pull-over-push pattern compliance."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        functions = extract_solidity_functions(code)

        for func_name, func_body, start_line in functions:
            cleaned_body = re.sub(r'//.*', '', func_body)
            cleaned_body = re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)

            # Mode 1: DoS via Block Gas Limit Scanner (External call inside a loop)
            # Find any loops (for, while) in the function body
            # Let's search for loop blocks
            loop_matches = re.finditer(r'\b(for|while)\b', cleaned_body)
            for loop_match in loop_matches:
                loop_start = loop_match.start()
                # Find loop brace or semicolon (in case of single statement loop, but usually brace)
                brace_idx = cleaned_body.find('{', loop_start)
                if brace_idx == -1:
                    continue

                # Find the end of the loop body by counting braces
                brace_count = 1
                curr_idx = brace_idx + 1
                body_len = len(cleaned_body)
                while curr_idx < body_len and brace_count > 0:
                    char = cleaned_body[curr_idx]
                    if char == '{':
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                    curr_idx += 1

                loop_body = cleaned_body[brace_idx:curr_idx]

                # Check if loop body contains external calls
                # Standard calls: .call{value: ...}, .call(...), .transfer(...), .send(...)
                # Or other interface calls like `token.transfer(`, `contract.method(`
                has_external_call = False
                if any(marker in loop_body for marker in [".call", ".transfer(", ".send(", ".transferFrom("]):
                    has_external_call = True

                # Also search for standard interface call pattern inside loop, excluding local variables
                # E.g., `instance.someMethod(`
                if not has_external_call:
                    interface_call_match = re.search(r'\b[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\s*\(', loop_body)
                    if interface_call_match:
                        # Exclude common gas-safe things like Math.min, Math.max, SafeMath.add
                        matched_call = interface_call_match.group(0)
                        if not any(safe in matched_call for safe in ["Math.", "SafeMath.", "abi.", "bytes.", "string."]):
                            has_external_call = True

                if has_external_call:
                    vulnerable_funcs.append(func_name)
                    flagged_findings.append(
                        f"Function '{func_name}' on Line {start_line} makes an external call inside a loop. "
                        f"If any of the external calls fail or revert, or if the number of loop iterations is large, "
                        f"the entire transaction will revert, blocking the contract from executing this function (Denial of Service)."
                    )

            # Mode 2: Pull-Over-Push Design Compliance
            # Check if contract is trying to distribute tokens/ether in a batch push (e.g. transfer in a loop to a list of users)
            if "for" in cleaned_body or "while" in cleaned_body:
                if any(transfer in cleaned_body for transfer in [".transfer(", "transfer(", "send("]) and "msg.sender" not in cleaned_body:
                    flagged_findings.append(
                        f"Push-Payment Pattern detected in loop within '{func_name}' on Line {start_line}. "
                        f"It is highly recommended to use a Pull-Payment (Claim/Withdrawal) design where each user "
                        f"individually triggers and pays the gas cost for their own transfers, eliminating block gas limit vulnerabilities."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_DOS_GAS_RISK"
            else:
                status = "WARN_DOS_GAS_RISK"
                is_secure = True

        return DoSGasLimitsOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
