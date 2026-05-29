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
    env_val = os.getenv("PI_ASSEMBLY_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_ASSEMBLY_STRICT_MODE", True))
        except Exception:
            pass
    return True

# 2. Pydantic-Enforced Input/Output Envelopes
class AssemblySafetyInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")

class AssemblySafetyOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract assembly usage is secure and optimized")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed assembly safety and optimization findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_ASSEMBLY_RISK, REJECTED_ASSEMBLY_RISK)")

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
class PiAssemblyLethalWeapons:
    """Specialized Web3 micro-agent that audits Solidity contracts for dangerous Yul/assembly memory practices and optimizes assembly syntax."""

    def __init__(self) -> None:
        self.agent_name = "PiAssemblyLethalWeapons"

    def audit_assembly(self, input_envelope: AssemblySafetyInput) -> AssemblySafetyOutput:
        """Autonomously audits Solidity contracts for assembly memory safety and optimization compliance."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        functions = extract_solidity_functions(code)

        for func_name, func_body, start_line in functions:
            cleaned_body = re.sub(r'//.*', '', func_body)
            cleaned_body = re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)

            # Check if using inline assembly
            if "assembly" in cleaned_body:
                # Mode 1: Assembly Memory Corruption Audit
                # Look for mstore or mstore8 that targets free memory pointer space (0x40) or lower (0x0 - 0x3f reserved slots)
                # E.g. "mstore(0x40, ...)" where the free memory pointer is updated without allocating correctly
                # Or direct writes to slots below 0x40.
                if re.search(r'\bmstore\(\s*(0x0|0x20|0|32)\s*,', cleaned_body) or re.search(r'\bmstore\(\s*(0x40|64)\s*,', cleaned_body):
                    # Flag as vulnerable if memory pointer is overwritten without proper alloc protection
                    if "allocate" not in cleaned_body.lower() and "free memory" not in cleaned_body.lower():
                        vulnerable_funcs.append(func_name)
                        flagged_findings.append(
                            f"Function '{func_name}' on Line {start_line} contains assembly that directly overwrites "
                            f"the free memory pointer (0x40) or reserved scratch space (0x00-0x3f). This can corrupt Solidity memory."
                        )

                # Mode 2: Assembly Optimizations (e.g. division by power of two instead of shr/shl, custom revert)
                # Search for div(x, 2) or div(x, power of two)
                div_match = re.search(r'\bdiv\(\s*([a-zA-Z0-9_]+)\s*,\s*(2|4|8|16|32|64|128|256)\s*\)', cleaned_body)
                if div_match:
                    flagged_findings.append(
                        f"Assembly Optimization: Function '{func_name}' on Line {start_line} uses 'div' division by "
                        f"a power of two in assembly. Using 'shr' (shift right) is more gas-efficient."
                    )

                # Search for mul(x, 2) or mul(x, power of two)
                mul_match = re.search(r'\bmul\(\s*([a-zA-Z0-9_]+)\s*,\s*(2|4|8|16|32|64|128|256)\s*\)', cleaned_body)
                if mul_match:
                    flagged_findings.append(
                        f"Assembly Optimization: Function '{func_name}' on Line {start_line} uses 'mul' multiplication by "
                        f"a power of two in assembly. Using 'shl' (shift left) is more gas-efficient."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ASSEMBLY_RISK"
            else:
                status = "WARN_ASSEMBLY_RISK"
                is_secure = True

        return AssemblySafetyOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
