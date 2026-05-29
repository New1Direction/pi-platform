from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_FLASH_LOAN_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_FLASH_LOAN_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class FlashLoanInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")
    allowed_pairs: List[str] = Field(
        default_factory=list, description="User-defined custom allowed pair addresses or safe pools"
    )


class FlashLoanOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from flash loan pricing vulnerabilities")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed line and violation findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ...,
        description="Status classification (PASSED, WARN_FLASH_LOAN_VULNERABILITY, REJECTED_FLASH_LOAN_VULNERABILITY)",
    )


# 3. Helper function to extract concrete Solidity functions
def extract_solidity_functions(solidity_code: str) -> List[Tuple[str, str, int]]:
    functions = []
    code_len = len(solidity_code)

    # Pattern matching "function [name] (" or "constructor ("
    pattern = re.compile(r"\b(function|constructor)\b\s*([a-zA-Z0-9_]*)\s*\(")

    for match in pattern.finditer(solidity_code):
        keyword = match.group(1)
        name = match.group(2)
        func_name = name if keyword == "function" else "constructor"

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
class PiFlashLoanDefender:
    """Specialized Web3 micro-agent that audits Solidity contracts for spot price manipulation and flash loan vectors."""

    def __init__(self) -> None:
        self.agent_name = "PiFlashLoanDefender"

    def audit_flash_loan(self, input_envelope: FlashLoanInput) -> FlashLoanOutput:
        """Autonomously scans Solidity functions for direct AMM spot reserve dependencies lacking oracles/TWAPs."""
        code = input_envelope.solidity_code
        functions = extract_solidity_functions(code)

        vulnerable_funcs = []
        flagged_findings = []

        # Spot reserve and direct pool balance lookup signatures
        spot_price_triggers = [
            "getreserves",
            "slot0",
            "uniswapv2pair",
            "uniswapv3pool",
            "balanceof(pair)",
            "balanceof(address(pair))",
            "pair.balanceof",
        ]

        # Safe decentralized pricing oracles and TWAPs
        secure_oracles = [
            "latestrounddata",
            "pricefeed",
            "aggregatorv3interface",
            "chainlink",
            "consult",
            "twap",
            "period",
            "pyth",
            "ipyth",
            "getlatestprice",
        ]

        for func_name, func_body, start_line in functions:
            if func_name == "constructor":
                continue

            # Clean body of comments to prevent false positives
            cleaned_body = re.sub(r"//.*", "", func_body)
            cleaned_body = re.sub(r"/\*.*?\*/", "", cleaned_body, flags=re.DOTALL)

            # Convert body to lowercase for matching
            body_lower = cleaned_body.lower()

            # Check for direct AMM spot reserve query triggers
            has_spot_query = any(trigger in body_lower for trigger in spot_price_triggers)

            # Also check if it does reserve/balance division or pricing math in the body
            # e.g. reserve0 / reserve1, res0 / res1, balance0 * 1e18 / balance1
            has_spot_math = False
            math_trigger = ""
            lines = cleaned_body.splitlines()
            for offset, line in enumerate(lines):
                line_num = start_line + offset
                stripped = line.strip().lower()

                # Check for reserve / balance division pattern
                # Matches: var1 / var2 or .getReserves results division
                if "/" in stripped:
                    # Filter out comment markers or local declarations
                    if not stripped.startswith("//") and not stripped.startswith("/*"):
                        # Match divisions involving reserve variables or balance variables
                        if any(term in stripped for term in ["reserve0", "reserve1", "res0", "res1", "balance"]):
                            has_spot_math = True
                            math_trigger = f"Direct reserve division '{stripped.strip()}' on Line {line_num}"
                            break

            # Check if this function relies on direct balance reading to get pricing
            # e.g. balanceOf(address(this)) to value assets
            has_direct_balance_pricing = "balanceof" in body_lower and any(
                kw in body_lower for kw in ["price", "value", "valuation", "getrate"]
            )

            # Evaluate if secure decentralized oracle or TWAP consult mechanism is integrated
            has_secure_oracle = any(oracle in body_lower for oracle in secure_oracles)

            # Identify violation
            if (has_spot_query or has_spot_math or has_direct_balance_pricing) and not has_secure_oracle:
                if func_name not in vulnerable_funcs:
                    vulnerable_funcs.append(func_name)

                reason = ""
                if has_spot_math:
                    reason = f"Function '{func_name}' calculates asset exchange rate directly via spot reserves ({math_trigger}) without decentralized oracle or TWAP defense."
                elif has_spot_query:
                    reason = f"Function '{func_name}' queries spot reserves/balances directly without incorporating Chainlink or TWAP price safeguards."
                else:
                    reason = f"Function '{func_name}' calculates asset value using direct contract token balance checks, exposing it to flash loan inflation."

                flagged_findings.append(reason)

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_FLASH_LOAN_VULNERABILITY"
            else:
                status = "WARN_FLASH_LOAN_VULNERABILITY"
                is_secure = True  # Warn only in non-strict mode

        return FlashLoanOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
