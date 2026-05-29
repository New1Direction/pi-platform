from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SIGNATURE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_SIGNATURE_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class SignatureInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")


class SignatureOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from signature replay issues")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed line and violation findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ...,
        description="Status classification (PASSED, WARN_SIGNATURE_REPLAY_VULNERABILITY, REJECTED_SIGNATURE_REPLAY_VULNERABILITY)",
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
class PiSignatureReplayScout:
    """Specialized Web3 micro-agent that audits Solidity contracts for signature replay vulnerabilities and EIP-712 compliance."""

    def __init__(self) -> None:
        self.agent_name = "PiSignatureReplayScout"

    def audit_signature(self, input_envelope: SignatureInput) -> SignatureOutput:
        """Autonomously audits Solidity contracts for signature recovery usage and replay protections."""
        code = input_envelope.solidity_code

        # Clean comments to avoid false positives in global analysis
        code_clean = re.sub(r"//.*", "", code)
        code_clean = re.sub(r"/\*.*?\*/", "", code_clean, flags=re.DOTALL)

        functions = extract_solidity_functions(code)

        vulnerable_funcs = []
        flagged_findings = []

        # Check globally if DOMAIN_SEPARATOR is defined
        has_domain_separator = "domain_separator" in code_clean.lower()

        for func_name, func_body, start_line in functions:
            if func_name == "constructor":
                continue

            # Clean comments for this function body
            cleaned_body = re.sub(r"//.*", "", func_body)
            cleaned_body = re.sub(r"/\*.*?\*/", "", cleaned_body, flags=re.DOTALL)

            body_lower = cleaned_body.lower()

            # Check if signature recovery is performed
            has_recovery = "ecrecover(" in body_lower or "ecdsa.recover(" in body_lower

            if has_recovery:
                # If EIP-712 standard is referenced via DOMAIN_SEPARATOR, we count it as safe/compliant (Mode 1 compliance)
                if has_domain_separator:
                    continue

                # Check for nonce tracking or chainId tracking in the function body
                has_nonce = "nonce" in body_lower
                has_chainid = "chainid" in body_lower

                if has_nonce or has_chainid:
                    continue

                # Otherwise, it might be vulnerable to replay attacks (Mode 2 vulnerability)
                lines = cleaned_body.splitlines()
                for offset, line in enumerate(lines):
                    line_num = start_line + offset
                    stripped = line.strip()
                    stripped_lower = stripped.lower()
                    if "ecrecover(" in stripped_lower or "ecdsa.recover(" in stripped_lower:
                        if func_name not in vulnerable_funcs:
                            vulnerable_funcs.append(func_name)

                        flagged_findings.append(
                            f"Function '{func_name}' recovers signature on Line {line_num}: '{stripped}' "
                            f"without references to EIP-712 structured data hashing (DOMAIN_SEPARATOR) "
                            f"or nonces/chainId replay tracking mechanisms."
                        )
                        break

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SIGNATURE_REPLAY_VULNERABILITY"
            else:
                status = "WARN_SIGNATURE_REPLAY_VULNERABILITY"
                is_secure = True  # Warn only in non-strict mode

        return SignatureOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
