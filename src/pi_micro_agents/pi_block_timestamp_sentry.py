from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_TIMESTAMP_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_TIMESTAMP_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class BlockTimestampInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")


class BlockTimestampOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from unsafe timestamp reliance")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed block.timestamp and expiration findings"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ...,
        description="Status classification (PASSED, WARN_TIMESTAMP_VULNERABILITY, REJECTED_TIMESTAMP_VULNERABILITY)",
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
class PiBlockTimestampSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for block.timestamp reliance issues and EIP-4337 expiration/timelock correctness."""

    def __init__(self) -> None:
        self.agent_name = "PiBlockTimestampSentry"

    def audit_timestamp(self, input_envelope: BlockTimestampInput) -> BlockTimestampOutput:
        """Autonomously audits Solidity contracts for block.timestamp/now reliance and expiration safety."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        functions = extract_solidity_functions(code)

        for func_name, func_body, start_line in functions:
            # Clean comments
            cleaned_body = re.sub(r"//.*", "", func_body)
            cleaned_body = re.sub(r"/\*.*?\*/", "", cleaned_body, flags=re.DOTALL)

            # Mode 1: Timestamp Reliance Check (Randomness generation, etc.)
            if "block.timestamp" in cleaned_body or "now" in cleaned_body:
                # Flag if used in keccak256 or random-like expressions or modulo
                if "%" in cleaned_body or "keccak256(" in cleaned_body or "random" in cleaned_body.lower():
                    vulnerable_funcs.append(func_name)
                    flagged_findings.append(
                        f"Function '{func_name}' on Line {start_line} relies on 'block.timestamp' for pseudo-randomness "
                        f"or entropy. Miners can manipulate timestamps within certain bounds, leading to exploitable randomness."
                    )

                # Mode 2: EIP-4337 Expiration Validation / Timelocks
                # Check if there are inequality checks but recommend standard time variance guards
                elif "<" in cleaned_body or ">" in cleaned_body:
                    # Verify if a standard margin or grace period exists
                    if not any(margin in cleaned_body for margin in ["day", "hour", "week", "86400", "3600"]):
                        flagged_findings.append(
                            f"Expiration warning: Function '{func_name}' on Line {start_line} compares 'block.timestamp' "
                            f"without using standard explicit time constants (like days, hours, or seconds margins), "
                            f"which can lead to precise deadline mismatch issues under varying network block congestion."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_TIMESTAMP_VULNERABILITY"
            else:
                status = "WARN_TIMESTAMP_VULNERABILITY"
                is_secure = True

        return BlockTimestampOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
