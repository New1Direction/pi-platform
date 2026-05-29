from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SELFDESTRUCT_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_SELFDESTRUCT_STRICT_MODE", True))
        except Exception:
            pass
    return True

# 2. Pydantic-Enforced Input/Output Envelopes
class SelfDestructHunterInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")

class SelfDestructHunterOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from unauthorized selfdestruct exploits")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed line and violation findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_SELFDESTRUCT_VULNERABILITY, REJECTED_SELFDESTRUCT_VULNERABILITY)")

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
class PiSelfDestructHunter:
    """Specialized Web3 micro-agent that audits Solidity contracts for selfdestruct and suicide operations and secure decommissioning."""

    def __init__(self) -> None:
        self.agent_name = "PiSelfDestructHunter"

    def audit_selfdestruct(self, input_envelope: SelfDestructHunterInput) -> SelfDestructHunterOutput:
        """Autonomously audits Solidity contracts for selfdestruct/suicide usage and pauses/decommissioning paths."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        functions = extract_solidity_functions(code)

        # Globally check if the contract supports Pausable/decommissioning best practices
        has_pause_mech = any(kw in code.lower() for kw in ["pause", "pausable", "ispaused", "expire", "expiration"])

        for func_name, func_body, start_line in functions:
            # Clean comments
            cleaned_body = re.sub(r'//.*', '', func_body)
            cleaned_body = re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)

            if "selfdestruct(" in cleaned_body or "suicide(" in cleaned_body:
                # Mode 1: SelfDestruct Exploit Scan - Check if ownership/access checks are present
                has_auth = any(mod in cleaned_body for mod in ["onlyOwner", "onlyAdmin", "hasRole"]) or \
                           any(req in cleaned_body.lower() for req in ["msg.sender == owner", "msg.sender == admin"])

                if not has_auth:
                    vulnerable_funcs.append(func_name)
                    flagged_findings.append(
                        f"Function '{func_name}' on Line {start_line} contains a selfdestruct call without active "
                        f"access control modifiers (like onlyOwner) or owner equality requirements, exposing the contract to theft."
                    )
                else:
                    # Mode 2: Contract Decommissioning Check - verify presence of secure pausing/transitions
                    if not has_pause_mech:
                        flagged_findings.append(
                            f"Decommissioning warning: Function '{func_name}' on Line {start_line} performs selfdestruct, "
                            f"but contract does not implement standard Pausable state transitions to safeguard funds prior to termination."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SELFDESTRUCT_VULNERABILITY"
            else:
                status = "WARN_SELFDESTRUCT_VULNERABILITY"
                is_secure = True

        return SelfDestructHunterOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
