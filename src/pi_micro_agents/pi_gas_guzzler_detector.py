from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
# is_strict_mode is now provided by pi_micro_agents.utils
# kept as a local shim for backward compatibility
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_GAS_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_GAS_STRICT_MODE", True))
        except Exception:
            pass
    return True

# 2. Pydantic-Enforced Input/Output Envelopes
class GasGuzzlerInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")

class GasGuzzlerOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from obvious gas-guzzling risks")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed gas guzzler findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_GAS_RISK, REJECTED_GAS_RISK)")

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
class PiGasGuzzlerDetector:
    """Specialized Web3 micro-agent that audits Solidity contracts for unbounded loops and general gas inefficiencies."""

    def __init__(self) -> None:
        self.agent_name = "PiGasGuzzlerDetector"

    def audit_gas(self, input_envelope: GasGuzzlerInput) -> GasGuzzlerOutput:
        """Autonomously audits Solidity contracts for gas-exhaustion loops and optimizations."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        functions = extract_solidity_functions(code)

        for func_name, func_body, start_line in functions:
            cleaned_body = re.sub(r'//.*', '', func_body)
            cleaned_body = re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)

            # Mode 1: Unbounded Loop Check (dynamically sized state array iteration)
            # Match for/while loop scanning length of an array without a local length cache
            # E.g. "i < users.length" where users is state variable
            if "for" in cleaned_body or "while" in cleaned_body:
                # Loop condition with a dynamic array lookup like .length
                length_match = re.search(r'\.\s*length\b', cleaned_body)
                if length_match:
                    # Let's see if there is no local length variable assigned (e.g. "uint256 len =")
                    if "length =" not in cleaned_body and "len =" not in cleaned_body:
                        vulnerable_funcs.append(func_name)
                        flagged_findings.append(
                            f"Function '{func_name}' on Line {start_line} contains a loop over a dynamic array's .length "
                            f"without caching it in memory. This wastes gas on each iteration and risks Out-Of-Gas block limits."
                        )

            # Mode 2: Gas Optimizations (Storage reads in loops, memory vs calldata)
            if "for" in cleaned_body or "while" in cleaned_body:
                # Match repeated storage reads inside the loop (e.g. state vars or map lookup)
                if cleaned_body.count("memory") == 0 and cleaned_body.count("calldata") == 0 and re.search(r'\b(s\.|storageVar|stateVar|mappingVar)\b', cleaned_body):
                    flagged_findings.append(
                        f"Gas Optimization: Function '{func_name}' on Line {start_line} contains a loop with potential direct "
                        f"storage variables access. Consider caching storage variables in memory before the loop."
                    )

            # memory instead of calldata for read-only arrays
            if "[] memory" in cleaned_body:
                # Check if array is not assigned to (i.e. read-only)
                # Quick check: no "array_name[index] =" or assignment. We just warn.
                flagged_findings.append(
                    f"Gas Optimization: Function '{func_name}' on Line {start_line} uses 'memory' instead of 'calldata' "
                    f"for an input array parameter. Declaring input parameters as 'calldata' is more gas-efficient."
                )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_GAS_RISK"
            else:
                status = "WARN_GAS_RISK"
                is_secure = True

        return GasGuzzlerOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
