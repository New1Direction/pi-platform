from __future__ import annotations

import re
from typing import List, Tuple

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
# is_strict_mode is now provided by pi_micro_agents.utils
# kept as a local shim for backward compatibility
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_LOGIC_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class LogicGatekeeperInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class LogicGatekeeperOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from logic tautologies and empty modifiers")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed logic gatekeeper findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_LOGIC_RISK, REJECTED_LOGIC_RISK)")


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
class PiLogicGatekeeper:
    """Specialized Web3 micro-agent that audits Solidity contracts for tautologies, empty modifiers, and unreachable dead code blocks."""

    def __init__(self) -> None:
        self.agent_name = "PiLogicGatekeeper"

    def audit_logic(self, input_envelope: LogicGatekeeperInput) -> LogicGatekeeperOutput:
        """Autonomously audits Solidity contracts for dead code, tautologies, and empty modifier bypasses."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Mode 1: Dead Code & Strict Logic Check (unreachable code, tautologies, empty modifiers)
        # Check for empty modifier overrides: e.g. "modifier onlyOwner() { _ ; }" but missing "_;" or containing only space
        modifier_pattern = re.compile(r"\bmodifier\b\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*\{([^}]*)\}")
        for match in modifier_pattern.finditer(code):
            mod_name = match.group(1)
            mod_body = match.group(3)
            # Clean comments
            cleaned_mod_body = re.sub(r"//.*", "", mod_body)
            cleaned_mod_body = re.sub(r"/\*.*?\*/", "", cleaned_mod_body, flags=re.DOTALL).strip()

            if "_;" not in cleaned_mod_body:
                vulnerable_funcs.append(mod_name)
                flagged_findings.append(
                    f"Modifier '{mod_name}' is defined without the required merge wildcard '_;'. "
                    f"This will cause any function using this modifier to bypass its entire body execution, causing severe silent logical bugs."
                )

        functions = extract_solidity_functions(code)

        for func_name, func_body, start_line in functions:
            cleaned_body = re.sub(r"//.*", "", func_body)
            cleaned_body = re.sub(r"/\*.*?\*/", "", cleaned_body, flags=re.DOTALL)

            # Unsigned comparison tautology (e.g., uint_var >= 0 or uint_var >= 0)
            # Match patterns like: ">= 0" or "< 0" for unsigned ints (assuming variables with uint/u prefix or explicitly uint)
            tautology_match = re.search(r"\b(uint256|uint8|uint160|uint|u)\s+([a-zA-Z0-9_]+)\b", cleaned_body)
            if tautology_match:
                var_name = tautology_match.group(2)
                # Check if this variable is compared to >= 0 or < 0
                if re.search(r"\b" + re.escape(var_name) + r"\s*>=\s*0\b", cleaned_body):
                    vulnerable_funcs.append(func_name)
                    flagged_findings.append(
                        f"Function '{func_name}' on Line {start_line} contains a tautological check comparing "
                        f"unsigned integer variable '{var_name}' >= 0. Unsigned integers are always greater than or equal to zero."
                    )
                elif re.search(r"\b" + re.escape(var_name) + r"\s*<\s*0\b", cleaned_body):
                    vulnerable_funcs.append(func_name)
                    flagged_findings.append(
                        f"Function '{func_name}' on Line {start_line} contains a tautological check comparing "
                        f"unsigned integer variable '{var_name}' < 0. Unsigned integers can never be negative."
                    )

            # Mode 2: Clean Code Compliance
            # Check for unreachable code after return or revert statements
            # Match "return x;" or "revert(...);" followed by active statements inside the same scope
            return_match = re.search(r"\b(return|revert|throw)\b[^;]*;\s*([a-zA-Z0-9_]+)", cleaned_body)
            if return_match:
                next_stmt = return_match.group(2)
                if next_stmt not in ["else", "catch", "finally", "modifier", "function"]:
                    flagged_findings.append(
                        f"Clean Code: Function '{func_name}' on Line {start_line} has unreachable code "
                        f"directly following a return, revert, or throw statement."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_LOGIC_RISK"
            else:
                status = "WARN_LOGIC_RISK"
                is_secure = True

        return LogicGatekeeperOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
