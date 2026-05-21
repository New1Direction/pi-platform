from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ARITHMETIC_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_ARITHMETIC_STRICT_MODE", True))
        except Exception:
            pass
    return True

# 2. Pydantic-Enforced Input/Output Envelopes
class ArithmeticInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")
    allowed_libraries: List[str] = Field(default_factory=list, description="Allowed safe math libraries")

class ArithmeticOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from arithmetic vulnerabilities")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed line and violation findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_ARITHMETIC_VULNERABILITY, REJECTED_ARITHMETIC_VULNERABILITY)")

# 3. Helper function to extract concrete Solidity functions
def extract_solidity_functions(solidity_code: str) -> List[Tuple[str, str, int]]:
    functions = []
    code_len = len(solidity_code)

    # Pattern matching "function [name] (" or "constructor ("
    pattern = re.compile(r'\b(function|constructor)\b\s*([a-zA-Z0-9_]*)\s*\(')

    for match in pattern.finditer(solidity_code):
        keyword = match.group(1)
        name = match.group(2)
        func_name = name if keyword == "function" else "constructor"

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
class PiArithmeticAuditor:
    """Specialized Web3 micro-agent that audits Solidity contracts for integer overflow and underflow vulnerabilities."""

    def __init__(self) -> None:
        self.agent_name = "PiArithmeticAuditor"

    def audit_arithmetic(self, input_envelope: ArithmeticInput) -> ArithmeticOutput:
        """Autonomously scans Solidity contracts for legacy arithmetic issues or modern unchecked blocks."""
        code = input_envelope.solidity_code
        functions = extract_solidity_functions(code)

        vulnerable_funcs = []
        flagged_findings = []

        # Check Solidity compiler version via pragma
        pragma_match = re.search(r'pragma\s+solidity\s+([^;]+);', code)
        pragma_version = pragma_match.group(1).strip() if pragma_match else ""

        # Determine if compiler version is legacy (<0.8.0)
        # Patterns like: 0.4.x, 0.5.x, 0.6.x, 0.7.x, or explicit lower bound < 0.8
        is_legacy_version = False
        if pragma_version:
            version_clean = pragma_version.replace(" ", "")
            # Check for version ranges or bounds
            if any(v in version_clean for v in ["0.4.", "0.5.", "0.6.", "0.7."]) or "<0.8" in version_clean or "<=0.7" in version_clean:
                is_legacy_version = True
        else:
            # If no pragma specified, strictly treat as legacy/vulnerable for safety
            is_legacy_version = True

        # Clean comments from the entire code first to check global properties accurately
        code_clean = re.sub(r'//.*', '', code)
        code_clean = re.sub(r'/\*.*?\*/', '', code_clean, flags=re.DOTALL)
        has_safemath_decl = "safemath" in code_clean.lower()

        for func_name, func_body, start_line in functions:
            if func_name == "constructor":
                continue

            # Clean comments to avoid false positives
            cleaned_body = re.sub(r'//.*', '', func_body)
            cleaned_body = re.sub(r'/\*.*?\*/', '', cleaned_body, flags=re.DOTALL)

            body_lower = cleaned_body.lower()

            # Scans for raw arithmetic operators (+, -, *) that perform computations
            # We must be careful not to match standard declarations or string patterns.
            # We look for lines containing: =, +=, -=, *= with variables and raw operators
            has_raw_math = False
            raw_math_trigger = ""

            lines = cleaned_body.splitlines()
            for offset, line in enumerate(lines):
                line_num = start_line + offset
                stripped = line.strip()

                # Check if it performs a mathematical assignment or operation
                # Exclude comment lines or standard require checks
                if not stripped.startswith("//") and not stripped.startswith("/*") and not stripped.startswith("import"):
                    # Look for operators + - * (excluding ++, --, comments)
                    # We match operators not followed by another operator
                    # Matching: + (but not ++), - (but not --), *
                    has_plus = "+" in stripped and "++" not in stripped and "+=" not in stripped
                    has_minus = "-" in stripped and "--" not in stripped and "-=" not in stripped
                    has_mul = "*" in stripped and "*=" not in stripped and "/*" not in stripped and "*/" not in stripped
                    has_assign_op = any(op in stripped for op in ["+=", "-=", "*="])

                    if (has_plus or has_minus or has_mul or has_assign_op) and "=" in stripped:
                        has_raw_math = True
                        raw_math_trigger = f"Raw arithmetic operator on Line {line_num}: '{stripped}'"
                        break

            # Check for modern Solidity unchecked blocks
            has_unchecked_block = "unchecked" in body_lower

            # Flag findings
            if is_legacy_version:
                # Legacy version (< 0.8.0) needs SafeMath
                # If they perform raw math and SafeMath is not used/declared, flag it
                has_safemath_call = any(sf in body_lower for sf in [".add(", ".sub(", ".mul(", ".div("])

                if has_raw_math and not has_safemath_call and not has_safemath_decl:
                    if func_name not in vulnerable_funcs:
                        vulnerable_funcs.append(func_name)
                    flagged_findings.append(
                        f"Legacy Solidity function '{func_name}' (pragma {pragma_version or 'unspecified'}) "
                        f"uses raw arithmetic operations ({raw_math_trigger}) without incorporating SafeMath libraries or bounds verification."
                    )
            else:
                # Modern version (>= 0.8.0)
                # If they use "unchecked" blocks, verify if raw math is handled inside.
                # Since unchecked disables compiler overflow bounds check, it warrants an advisory warning
                if has_unchecked_block and has_raw_math:
                    if func_name not in vulnerable_funcs:
                        vulnerable_funcs.append(func_name)
                    flagged_findings.append(
                        f"Function '{func_name}' performs computations inside an 'unchecked' block ({raw_math_trigger}), "
                        f"which disables Solidity 0.8+ compiler safety checks and may introduce integer overflow/underflow vectors."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ARITHMETIC_VULNERABILITY"
            else:
                status = "WARN_ARITHMETIC_VULNERABILITY"
                is_secure = True  # Warn only in non-strict mode

        return ArithmeticOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
