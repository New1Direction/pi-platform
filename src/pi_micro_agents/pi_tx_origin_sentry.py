from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_TXORIGIN_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_TXORIGIN_STRICT_MODE", True))
        except Exception:
            pass
    return True

# 2. Pydantic-Enforced Input/Output Envelopes
class TxOriginInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")

class TxOriginOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from unsafe tx.origin authentication")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed tx.origin and EIP-2771 compliance findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_TXORIGIN_VULNERABILITY, REJECTED_TXORIGIN_VULNERABILITY)")

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
class PiTxOriginSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for tx.origin phishing risk and EIP-2771 compliance."""

    def __init__(self) -> None:
        self.agent_name = "PiTxOriginSentry"

    def audit_tx_origin(self, input_envelope: TxOriginInput) -> TxOriginOutput:
        """Autonomously audits Solidity contracts for tx.origin authorizations and meta-transaction overrides."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        functions = extract_solidity_functions(code)

        # Globally check if the contract is designed to support EIP-2771 meta-transactions
        is_eip2771_compliant = "erc2771" in code.lower() or "istrustedforwarder" in code.lower()

        for func_name, func_body, start_line in functions:
            # Clean comments
            cleaned_body = re.sub(r'//.*', '', func_body)
            cleaned_body = re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)

            # Mode 1: tx.origin Phishing Scan
            if "tx.origin" in cleaned_body:
                vulnerable_funcs.append(func_name)
                flagged_findings.append(
                    f"Function '{func_name}' on Line {start_line} uses 'tx.origin' for authorization/verification, "
                    f"which makes the contract highly vulnerable to phishing attacks (via malicious intermediary smart contracts)."
                )

            # Mode 2: EIP-2771 Compliance Check
            if is_eip2771_compliant and "msg.sender" in cleaned_body:
                # If meta-transaction capable, recommend using _msgSender() instead of msg.sender
                if "_msgSender(" not in cleaned_body:
                    flagged_findings.append(
                        f"Compliance warning: Function '{func_name}' on Line {start_line} accesses msg.sender directly "
                        f"in an ERC-2771 context. Recommend using standard EIP-2771 message sender helper '_msgSender()' instead."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_TXORIGIN_VULNERABILITY"
            else:
                status = "WARN_TXORIGIN_VULNERABILITY"
                is_secure = True

        return TxOriginOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
