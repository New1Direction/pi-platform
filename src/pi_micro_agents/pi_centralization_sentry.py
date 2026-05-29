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
    env_val = os.getenv("PI_CENTRALIZATION_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_CENTRALIZATION_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class CentralizationInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class CentralizationOutput(BaseModel):
    is_secure: bool = Field(
        ..., description="Indicates if contract admin operations have appropriate decentralized protections"
    )
    vulnerable_functions: List[str] = Field(
        default_factory=list, description="Vulnerable function names or variable names"
    )
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed centralization risk findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_CENTRALIZATION_RISK, REJECTED_CENTRALIZATION_RISK)"
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
class PiCentralizationSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for centralization risks and timelock compliance."""

    def __init__(self) -> None:
        self.agent_name = "PiCentralizationSentry"

    def audit_centralization(self, input_envelope: CentralizationInput) -> CentralizationOutput:
        """Autonomously audits Solidity contracts for centralization risk parameters and EIP timelocks."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        functions = extract_solidity_functions(code)

        for func_name, func_body, start_line in functions:
            cleaned_body = re.sub(r"//.*", "", func_body)
            cleaned_body = re.sub(r"/\*.*?\*/", "", cleaned_body, flags=re.DOTALL)

            # Mode 1: Centralization Risk Check (administrative minting or pause controls lacking delay/approval)
            # Find sensitive keywords: "mint", "pause", "unpause", "setFee", "withdrawFees" combined with "onlyOwner" or "onlyAdmin"
            if any(action in func_name.lower() for action in ["mint", "pause", "unpause", "fee", "withdraw"]):
                if any(mod in func_body for mod in ["onlyOwner", "onlyAdmin", "onlyRole"]):
                    # Flag as vulnerable centralization risk if there are no delays or multiple signatures required
                    if not any(
                        safe in cleaned_body.lower()
                        for safe in ["timelock", "delay", "propose", "execute", "multisig", "threshold"]
                    ):
                        vulnerable_funcs.append(func_name)
                        flagged_findings.append(
                            f"Centralization Risk: Admin function '{func_name}' on Line {start_line} allows instant execution "
                            f"of highly privileged action without explicit timelocks or multi-signature consensus steps."
                        )

            # Mode 2: Multi-Sig/Timelock Setup Verification
            # If function looks like timelock setter or updater, check minimum delay bounds
            if "timelock" in func_name.lower() or "delay" in func_name.lower():
                if "delay" in cleaned_body.lower() and "<" in cleaned_body:
                    # Recommend a solid safety limit (e.g. at least 2 days / 172800 seconds)
                    if not any(limit in cleaned_body for limit in ["172800", "2 days", "48 hours"]):
                        flagged_findings.append(
                            f"Timelock Compliance warning: Function '{func_name}' on Line {start_line} updates timelock delay parameters "
                            f"but does not enforce a secure minimum floor bounds (e.g. 2 days delay)."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_CENTRALIZATION_RISK"
            else:
                status = "WARN_CENTRALIZATION_RISK"
                is_secure = True

        return CentralizationOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
