from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_TOKENTAX_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_TOKENTAX_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class TokenTaxInput(BaseModel):
    file_path: str = Field(..., description="Solidity token contract file path")
    solidity_code: str = Field(..., description="Solidity ERC-20 source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")


class TokenTaxOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from hidden token taxes and compliant")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed tax and interface findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_TOKENTAX_VULNERABILITY, REJECTED_TOKENTAX_VULNERABILITY)"
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
class PiTokenTaxDetector:
    """Specialized Web3 micro-agent that audits ERC-20 transfer mechanisms for hidden taxes, burn fees, and standards compliance."""

    def __init__(self) -> None:
        self.agent_name = "PiTokenTaxDetector"

    def audit_token_tax(self, input_envelope: TokenTaxInput) -> TokenTaxOutput:
        """Autonomously audits Solidity ERC-20 contracts for taxes and compliant interface signatures."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        functions = extract_solidity_functions(code)

        for func_name, func_body, start_line in functions:
            # Clean comments
            cleaned_body = re.sub(r"//.*", "", func_body)
            cleaned_body = re.sub(r"/\*.*?\*/", "", cleaned_body, flags=re.DOTALL)

            if func_name in ["transfer", "transferFrom"]:
                # Mode 1: Token Tax Audit
                # Check for arithmetic operations on 'amount' or calculations suggesting deduction of fee or transfer tax
                tax_pattern = re.compile(r"\b(fee|tax|burn|basisPoints|rate|pct)\b")
                if tax_pattern.search(cleaned_body) and any(op in cleaned_body for op in ["-", "*", "/"]):
                    vulnerable_funcs.append(func_name)
                    flagged_findings.append(
                        f"Function '{func_name}' on Line {start_line} contains operations using fee/tax variables "
                        f"which indicates a potential 'fee-on-transfer' or dynamic transfer tax mechanism."
                    )

                # Check for blacklist/whitelist exclusion checks
                if any(kw in cleaned_body.lower() for kw in ["exclude", "blacklist", "whitelist"]):
                    if func_name not in vulnerable_funcs:
                        vulnerable_funcs.append(func_name)
                    flagged_findings.append(
                        f"Function '{func_name}' on Line {start_line} contains exclusion or whitelist checks, "
                        f"which could act as backdoors to bypass taxes for privileged addresses."
                    )

                # Mode 2: ERC-20 Interface Compliance
                # Standard transfer functions should return a boolean
                if "returns" in func_body and "bool" not in func_body:
                    flagged_findings.append(
                        f"Compliance warning: Function '{func_name}' on Line {start_line} does not explicitly return a boolean value "
                        f"as required by the standard ERC-20 specification."
                    )

                # Standard transfer functions must emit Transfer event
                if "emit Transfer(" not in cleaned_body:
                    flagged_findings.append(
                        f"Compliance warning: Function '{func_name}' on Line {start_line} does not emit the required 'Transfer' event."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_TOKENTAX_VULNERABILITY"
            else:
                status = "WARN_TOKENTAX_VULNERABILITY"
                is_secure = True

        return TokenTaxOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
