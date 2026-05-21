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
    env_val = os.getenv("PI_PHISHING_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_PHISHING_STRICT_MODE", True))
        except Exception:
            pass
    return True

# 2. Pydantic-Enforced Input/Output Envelopes
class PhishingShieldInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")

class PhishingShieldOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from message-sender phishing vulnerabilities")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed phishing shield findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_PHISHING_RISK, REJECTED_PHISHING_RISK)")

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
class PiPhishingShield:
    """Specialized Web3 micro-agent that audits Solidity contracts for callback msg.sender phishing and gasless signature compliance."""

    def __init__(self) -> None:
        self.agent_name = "PiPhishingShield"

    def audit_phishing(self, input_envelope: PhishingShieldInput) -> PhishingShieldOutput:
        """Autonomously audits Solidity contracts for phishing vectors and signature permit compliance."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        functions = extract_solidity_functions(code)

        for func_name, func_body, start_line in functions:
            cleaned_body = re.sub(r'//.*', '', func_body)
            cleaned_body = re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)

            # Mode 1: msg.sender Phishing Vector check (using msg.sender for callback validation)
            # Find callback patterns like "onTokenTransfer" or "tokensReceived" or external hook execution
            # E.g. "onTokenTransfer(address sender, ...)" but verifying caller is msg.sender without verification
            if "ontokentransfer" in func_name.lower() or "tokensreceived" in func_name.lower():
                if "msg.sender" in cleaned_body and not any(check in cleaned_body for check in ["require(", "revert("]):
                    vulnerable_funcs.append(func_name)
                    flagged_findings.append(
                        f"Function '{func_name}' on Line {start_line} acts as a token transfer callback "
                        f"but accesses 'msg.sender' without explicit validation or require gates, risking message-sender phishing attacks."
                    )

            # Mode 2: EIP-3009/EIP-2612 Permit Compliance Check
            # If function looks like signature permit verifier, verify deadline checking exists
            if "permit" in func_name.lower():
                # Signature permit needs deadline validation (must verify block.timestamp <= deadline)
                if "deadline" in cleaned_body.lower() and not any(cond in cleaned_body.lower() for cond in ["block.timestamp", "now"]):
                    flagged_findings.append(
                        f"Permit Warning: Function '{func_name}' on Line {start_line} accepts a 'deadline' parameter "
                        f"but does not validate it against the current block.timestamp, violating EIP-2612 specification guidelines."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_PHISHING_RISK"
            else:
                status = "WARN_PHISHING_RISK"
                is_secure = True

        return PhishingShieldOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
