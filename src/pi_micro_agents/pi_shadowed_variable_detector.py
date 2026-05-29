from __future__ import annotations

import re
from typing import List, Tuple

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_SHADOW_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class ShadowedVariableInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")


class ShadowedVariableOutput(BaseModel):
    is_secure: bool = Field(
        ..., description="Indicates if contract is free from variable shadowing and unused variable issues"
    )
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed shadowing and unused variable findings"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_SHADOW_VULNERABILITY, REJECTED_SHADOW_VULNERABILITY)"
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
class PiShadowedVariableDetector:
    """Specialized Web3 micro-agent that audits Solidity contracts for state-level variable shadowing and unused functions/parameters."""

    def __init__(self) -> None:
        self.agent_name = "PiShadowedVariableDetector"

    def audit_shadowed(self, input_envelope: ShadowedVariableInput) -> ShadowedVariableOutput:
        """Autonomously audits Solidity contracts for shadowed and unused variables."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Clean comments
        code_clean = re.sub(r"//.*", "", code)
        code_clean = re.sub(r"/\*.*?\*/", "", code_clean, flags=re.DOTALL)

        # Collect state variables
        state_var_pattern = re.compile(
            r"\b(address|uint256|bytes32|bool|string)\b\s+(?:public|private|internal)?\s*(?!constant|immutable)([a-zA-Z0-9_]+)\s*;"
        )
        state_vars = [match.group(2) for match in state_var_pattern.finditer(code_clean)]

        functions = extract_solidity_functions(code)

        for func_name, func_body, start_line in functions:
            # Clean comments for func body
            cleaned_body = re.sub(r"//.*", "", func_body)
            cleaned_body = re.sub(r"/\*.*?\*/", "", cleaned_body, flags=re.DOTALL)

            # Extract parameter list: get parameter contents inside function header
            # pattern matches function [name]([params])
            param_match = re.search(r"\b(?:function|constructor)\b\s*[a-zA-Z0-9_]*\s*\(([^)]*)\)", cleaned_body)
            params = []
            if param_match:
                param_block = param_match.group(1)
                # Split parameters by comma and clean
                raw_params = param_block.split(",")
                for rp in raw_params:
                    parts = rp.strip().split()
                    if parts:
                        # The variable name is usually the last word
                        var_name = parts[-1].strip()
                        if (
                            var_name.startswith("memory")
                            or var_name.startswith("calldata")
                            or var_name.startswith("storage")
                        ):
                            if len(parts) >= 2:
                                var_name = parts[-2].strip()
                        # Sanitize identifier
                        var_name = re.sub(r"[^a-zA-Z0-9_]", "", var_name)
                        if var_name:
                            params.append(var_name)

            # Mode 1: Variable Shadowing Scan
            for param in params:
                if param in state_vars:
                    vulnerable_funcs.append(func_name)
                    flagged_findings.append(
                        f"Function '{func_name}' on Line {start_line} contains parameter '{param}' "
                        f"which shadows a state-level variable declaration with the same name. "
                        f"This shadowing can lead to logic errors and security oversights."
                    )

            # Mode 2: Unused Variables Audit
            # Check if parameter is referenced inside the function body (after function header)
            brace_idx = cleaned_body.find("{")
            if brace_idx != -1:
                body_only = cleaned_body[brace_idx + 1 :]
                for param in params:
                    # Search for references to param name
                    param_ref_pattern = re.compile(r"\b" + re.escape(param) + r"\b")
                    if not param_ref_pattern.search(body_only):
                        # Ensure we don't flag if it's already shadowed
                        if func_name not in vulnerable_funcs:
                            flagged_findings.append(
                                f"Optimization warning: Function '{func_name}' on Line {start_line} declares "
                                f"parameter '{param}' which is never used in the function body. "
                                f"Remove unused parameters to save gas on deployment and execution."
                            )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SHADOW_VULNERABILITY"
            else:
                status = "WARN_SHADOW_VULNERABILITY"
                is_secure = True

        return ShadowedVariableOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
