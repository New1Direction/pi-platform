from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_UNINITIALIZED_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_UNINITIALIZED_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class UninitializedInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")


class UninitializedOutput(BaseModel):
    is_secure: bool = Field(
        ..., description="Indicates if contract is free from uninitialized storage variables and initializer issues"
    )
    vulnerable_functions: List[str] = Field(
        default_factory=list, description="Vulnerable function names or variable names"
    )
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed uninitialized storage and initializer findings"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_UNINITIALIZED_STATE, REJECTED_UNINITIALIZED_STATE)"
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
class PiUninitializedStateSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for uninitialized storage state variables and proxy initializer correctness."""

    def __init__(self) -> None:
        self.agent_name = "PiUninitializedStateSentry"

    def audit_uninitialized(self, input_envelope: UninitializedInput) -> UninitializedOutput:
        """Autonomously audits Solidity contracts for uninitialized storage variables and initializer functions."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Clean comments
        code_clean = re.sub(r"//.*", "", code)
        code_clean = re.sub(r"/\*.*?\*/", "", code_clean, flags=re.DOTALL)

        functions = extract_solidity_functions(code)

        # Mode 1: Uninitialized Storage Scan
        # Find state variables (declared in contract scope but not inside functions, struct, or constructor)
        # We can scan for declarations like "[type] public/private [name];" that are not initialized inline
        state_var_pattern = re.compile(
            r"\b(address|uint256|bytes32|bool)\b\s+(?:public|private|internal)?\s*(?!constant|immutable)([a-zA-Z0-9_]+)\s*;"
        )

        # Collect declared state variables
        state_vars = []
        for match in state_var_pattern.finditer(code_clean):
            var_type = match.group(1)
            var_name = match.group(2)
            # Find the line number
            line_num = code[: match.start()].count("\n") + 1
            state_vars.append((var_name, var_type, line_num))

        # Check constructor and initialization functions to see if state variables are set
        init_blocks = ""
        for func_name, func_body, _ in functions:
            if func_name in ["constructor", "initialize"]:
                # Clean comments in func body
                cleaned_func = re.sub(r"//.*", "", func_body)
                cleaned_func = re.sub(r"/\*.*?\*/", "", cleaned_func, flags=re.DOTALL)
                init_blocks += " " + cleaned_func

        for var_name, _var_type, line_num in state_vars:
            # Simple check if variable name is assigned to inside constructor/initialize block (e.g. "var_name =")
            assignment_pattern = re.compile(r"\b" + re.escape(var_name) + r"\s*=")
            if not assignment_pattern.search(init_blocks) and not re.search(
                r"\b" + re.escape(var_name) + r"\s*=\s*[^\s;]+", code_clean
            ):
                vulnerable_funcs.append(var_name)
                flagged_findings.append(
                    f"State variable '{var_name}' declared on Line {line_num} is never initialized "
                    f"inline or inside constructor/initialize functions, leading to potentially dangerous uninitialized storage states."
                )

        # Mode 2: Upgradeable Proxy Initializer check
        # Check if inherits OpenZeppelin Upgradeable base and defines "initialize" function
        is_upgradeable = "upgradeable" in code_clean.lower()
        if is_upgradeable:
            for func_name, func_body, start_line in functions:
                if func_name == "initialize":
                    # It must have initializer modifier
                    if "initializer" not in func_body:
                        vulnerable_funcs.append(func_name)
                        flagged_findings.append(
                            f"Function '{func_name}' on Line {start_line} is missing the OpenZeppelin 'initializer' modifier, "
                            f"making the upgradeable proxy initialization vulnerable to frontrunning re-initializations."
                        )

                    # It must invoke parent init calls, e.g. if ERC20Upgradeable is present, it must call __ERC20_init()
                    if "erc20upgradeable" in code_clean.lower() and "__erc20_init" not in func_body.lower():
                        vulnerable_funcs.append(func_name)
                        flagged_findings.append(
                            f"Function '{func_name}' on Line {start_line} inherits ERC20Upgradeable "
                            f"but does not invoke the parent initializer __ERC20_init(), leaving parent variables uninitialized."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_UNINITIALIZED_STATE"
            else:
                status = "WARN_UNINITIALIZED_STATE"
                is_secure = True

        return UninitializedOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
