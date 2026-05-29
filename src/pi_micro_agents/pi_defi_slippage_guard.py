from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SLIPPAGE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_SLIPPAGE_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class DeFiSlippageInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class DeFiSlippageOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if DeFi swap calls have proper slippage protection")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed slippage security and optimization findings"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_SLIPPAGE_RISK, REJECTED_SLIPPAGE_RISK)")


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
class PiDeFiSlippageGuard:
    """Specialized Web3 micro-agent that audits DeFi swap integrations for zero-slippage sandwich attack vulnerabilities."""

    def __init__(self) -> None:
        self.agent_name = "PiDeFiSlippageGuard"

    def audit_slippage(self, input_envelope: DeFiSlippageInput) -> DeFiSlippageOutput:
        """Autonomously audits Solidity contracts for Uniswap/DeFi zero slippage inputs and validates custom slippage parameters."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        functions = extract_solidity_functions(code)

        for func_name, func_body, start_line in functions:
            cleaned_body = re.sub(r"//.*", "", func_body)
            cleaned_body = re.sub(r"/\*.*?\*/", "", cleaned_body, flags=re.DOTALL)

            # Mode 1: Zero Slippage Uniswap Swaps Scan
            # Identify calls to swap methods of Uniswap V2/V3 Router or standard dex routers
            # E.g. swapExactTokensForTokens, swapExactETHForTokens, swapTokensForExactTokens, swapExactTokensForETH, swap
            swap_match = re.search(
                r"\b(swapExact[a-zA-Z0-9_]*|swap[a-zA-Z0-9_]*Exact[a-zA-Z0-9_]*|swap)\b\s*\(", cleaned_body
            )
            if swap_match:
                # Let's inspect the arguments of the swap call.
                # Specifically, we look for hardcoded '0' or 'uint256(0)' as one of the parameters.
                # In Uniswap V2, amountOutMin is the second argument: swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline)
                # In general, if there is a '0' or 'uint256(0)' preceded by a comma and followed by a comma (or close parenthesis)
                # representing amountOutMin, let's flag it.
                # E.g. swapExactTokensForTokens(..., 0, ...)
                zero_slippage_match = re.search(
                    r"\b(swapExact[a-zA-Z0-9_]*|swap[a-zA-Z0-9_]*Exact[a-zA-Z0-9_]*|swap)\b\s*\(\s*([^;]+)\s*\)",
                    cleaned_body,
                    re.DOTALL,
                )
                if zero_slippage_match:
                    args_str = zero_slippage_match.group(2)
                    args = [arg.strip() for arg in args_str.split(",")]

                    # If the number of arguments suggests Uniswap swap signature
                    # amountOutMin is typically the second arg, but any arg being exactly '0' or 'uint256(0)' is highly suspicious.
                    is_zero = False
                    for arg in args:
                        if arg == "0" or arg == "uint256(0)" or arg == "uint(0)":
                            is_zero = True
                            break

                    if is_zero:
                        vulnerable_funcs.append(func_name)
                        flagged_findings.append(
                            f"Function '{func_name}' on Line {start_line} performs a DeFi swap with a hardcoded minimum output "
                            f"parameter set to 0 (e.g. amountOutMin = 0). This removes slippage protection entirely, "
                            f"making the transaction extremely vulnerable to front-running sandwich attacks."
                        )

            # Mode 2: Slippage Setting Check
            # Ensure the function exposes a dynamic user-controlled amountOutMin or slippage parameter.
            # If the function does a swap but its function arguments don't have "amountOutMin" or "slippage" or "minAmount" or "minReturn",
            # we suggest adding slippage settings.
            if swap_match:
                # Get the function signature definition
                sig_match = re.match(r"\b(function|constructor)\b\s*([a-zA-Z0-9_]*)\s*\(([^)]*)\)", func_body)
                if sig_match:
                    params_str = sig_match.group(3).lower()
                    if not any(
                        keyword in params_str
                        for keyword in ["slippage", "minamount", "amountoutmin", "minreturn", "minout"]
                    ):
                        flagged_findings.append(
                            f"DeFi Integration Check: Function '{func_name}' on Line {start_line} wraps a swap but "
                            f"does not accept a dynamic user-defined or oracle-derived slippage limit or amountOutMin parameter. "
                            f"It is recommended to allow the caller to specify their slippage tolerance dynamically."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SLIPPAGE_RISK"
            else:
                status = "WARN_SLIPPAGE_RISK"
                is_secure = True

        return DeFiSlippageOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
