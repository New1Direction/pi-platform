from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_REENTRANCY_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_REENTRANCY_STRICT_MODE", True))
        except Exception:
            pass
    return True

# 2. Pydantic-Enforced Input/Output Envelopes
class ReentrancyInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")

class ReentrancyOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from reentrancy vulnerabilities")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed line and violation findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_REENTRANCY, REJECTED_REENTRANCY)")

# 3. Helper function to extract concrete Solidity functions
def extract_solidity_functions(solidity_code: str) -> List[Tuple[str, str, int]]:
    functions = []
    code_len = len(solidity_code)

    # Pattern matching "function [name] ("
    pattern = re.compile(r'\bfunction\s+([a-zA-Z0-9_]+)\s*\(')

    for match in pattern.finditer(solidity_code):
        func_name = match.group(1)
        start_idx = match.start()

        # Calculate line number of start_idx
        start_line = solidity_code[:start_idx].count('\n') + 1

        # Semicolons and opening braces determine concrete vs abstract functions
        semicolon_idx = solidity_code.find(';', start_idx)
        brace_idx = solidity_code.find('{', start_idx)

        if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx):
            continue

        # Match braces to find full function block body
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

# 4. Core Micro-Agent Class
class PiReentrancySentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for checks-effects-interactions reentrancy violations."""

    def __init__(self) -> None:
        self.agent_name = "PiReentrancySentry"

    def audit_reentrancy(self, input_envelope: ReentrancyInput) -> ReentrancyOutput:
        """Autonomously scans Solidity functions for unsafe external call patterns."""
        code = input_envelope.solidity_code
        functions = extract_solidity_functions(code)

        vulnerable_funcs = []
        flagged_findings = []

        for func_name, func_body, start_line in functions:
            # 1. Clean body (strip comments to prevent false positives in commented out code)
            cleaned_body = re.sub(r'//.*', '', func_body)
            cleaned_body = re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)

            # 2. Check for standard reentrancy guard modifiers (e.g. nonReentrant)
            # Find declaration line (first line of func_body or declaration text prior to first opening brace)
            # We can check if nonReentrant exists in the body definition or modifier context
            if "nonreentrant" in func_body.lower():
                continue

            body_lines = cleaned_body.splitlines()

            external_call_lines: List[Tuple[int, str]] = []
            state_update_lines: List[Tuple[int, str]] = []

            for offset_idx, line in enumerate(body_lines):
                line_num = start_line + offset_idx
                stripped = line.strip()
                if not stripped:
                    continue

                # Search for external call signatures:
                # e.g., msg.sender.call{value: ...}(""), addr.send(...), token.transfer(...)
                is_ext_call = False
                if ".call{" in stripped or ".call(" in stripped:
                    is_ext_call = True
                elif ".send(" in stripped or ".transfer(" in stripped:
                    # Exclude standard Solidity require statement conditions on transfer checks
                    if not stripped.startswith("require") and not stripped.startswith("assert"):
                        is_ext_call = True
                elif "delegatecall(" in stripped:
                    is_ext_call = True

                if is_ext_call:
                    external_call_lines.append((line_num, stripped))

                # Search for state updates/modifications:
                # e.g. stateVar = ..., balances[x] -= ..., allowed[x][y] = ..., stateVar.push(...)
                # Exclude lines that are comparison operators (==, <=, >=, !=)
                is_state_update = False

                # Check for standard assignments (+=, -=, =, ++, --)
                # Ensure it's not a comparison or local variable declaration (unless local var references state)
                # But to be safe and accurate: any assignment containing balances/owner/state updates
                if any(op in stripped for op in ["=", "+=", "-=", "++", "--"]):
                    # Exclude comparison checks in conditions
                    if not any(comp in stripped for comp in ["==", "<=", ">=", "!=", "require", "if (", "if("]):
                        # Ignore standard memory/local declarations like "uint amount =" or "address owner =" unless modifying state
                        if not stripped.startswith("uint") and not stripped.startswith("address ") and not stripped.startswith("bool "):
                            is_state_update = True
                        elif "[" in stripped or "balances" in stripped:
                            # State variables or mapping modifications often contain brackets or balance indicators
                            is_state_update = True
                elif stripped.startswith("delete "):
                    is_state_update = True
                elif ".push(" in stripped:
                    is_state_update = True

                if is_state_update:
                    state_update_lines.append((line_num, stripped))

            # 3. Detect Checks-Effects-Interactions violation:
            # If an external call happened on a line index before any state update
            for call_line, call_content in external_call_lines:
                violating_updates = [up for up in state_update_lines if up[0] > call_line]
                if violating_updates:
                    if func_name not in vulnerable_funcs:
                        vulnerable_funcs.append(func_name)
                    for up_line, up_content in violating_updates:
                        flagged_findings.append(
                            f"Checks-Effects-Interactions violation in function '{func_name}': "
                            f"State update '{up_content}' on Line {up_line} occurs after external call "
                            f"'{call_content}' on Line {call_line}."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_REENTRANCY"
            else:
                status = "WARN_REENTRANCY"
                is_secure = True # Warn only in non-strict mode

        return ReentrancyOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
