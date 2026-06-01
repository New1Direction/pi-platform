from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_UPGRADE_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class UpgradeDefectInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class UpgradeDefectOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract upgrade patterns are secure")
    vulnerable_functions: List[str] = Field(
        default_factory=list, description="Vulnerable function names or contract names"
    )
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed upgradeability findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_UPGRADE_RISK, REJECTED_UPGRADE_RISK)")


# Helper to check if a line is within a function
def is_inside_function(solidity_code: str, index: int) -> bool:
    # Find the last function definition before index and check braces
    func_pattern = re.compile(r"\b(function|constructor|fallback|receive)\b")
    func_matches = list(func_pattern.finditer(solidity_code[:index]))
    if not func_matches:
        return False

    # Check if the closest function braces contain the index
    last_match = func_matches[-1]
    start_idx = last_match.start()
    brace_idx = solidity_code.find("{", start_idx)
    if brace_idx == -1 or brace_idx > index:
        return False

    brace_count = 1
    curr_idx = brace_idx + 1
    code_len = len(solidity_code)
    while curr_idx < code_len and brace_count > 0:
        if curr_idx == index:
            return True
        char = solidity_code[curr_idx]
        if char == "{":
            brace_count += 1
        elif char == "}":
            brace_count -= 1
        curr_idx += 1

    return False


# 3. Core Micro-Agent Class
class PiUpgradeDefectDetector:
    """Specialized Web3 micro-agent that audits upgradeable contracts for storage collisions, missing gaps, and proxy initialization defects."""

    def __init__(self) -> None:
        self.agent_name = "PiUpgradeDefectDetector"

    def audit_upgrade(self, input_envelope: UpgradeDefectInput) -> UpgradeDefectOutput:
        """Autonomously audits Solidity contracts for storage gaps and unsafe state variable initializations in upgradeable systems."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find contract names
        contract_matches = re.finditer(r"\bcontract\s+([a-zA-Z0-9_]+)", code)
        for contract_match in contract_matches:
            contract_name = contract_match.group(1)

            # Determine contract body limits
            start_idx = contract_match.end()
            brace_idx = code.find("{", start_idx)
            if brace_idx == -1:
                continue

            brace_count = 1
            curr_idx = brace_idx + 1
            code_len = len(code)
            while curr_idx < code_len and brace_count > 0:
                char = code[curr_idx]
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                curr_idx += 1
            contract_body = code[brace_idx:curr_idx]

            # Check if this contract is upgradeable (inherits from Upgradeable, Initializable, or defines an initialize function)
            is_upgradeable = False
            inherits_clause = code[contract_match.start() : brace_idx]
            if (
                "upgradeable" in inherits_clause.lower()
                or "initializable" in inherits_clause.lower()
                or "initialize" in contract_body.lower()
            ):
                is_upgradeable = True

            if not is_upgradeable:
                continue

            # Mode 1: Storage Collision Scan (Missing __gap variable in upgradeable contracts)
            # Find if there is a storage gap declared: e.g. "uint256[50] private __gap" or "__gap" or "gap"
            gap_match = re.search(r"\b__gap\b|\bgap\b", contract_body)
            if not gap_match:
                # Check if it declares any state variables. If it does not declare state variables, maybe it's fine,
                # but typically all upgradeable parent contracts should define a storage gap.
                vulnerable_funcs.append(contract_name)
                flagged_findings.append(
                    f"Upgradeable contract '{contract_name}' does not declare a storage gap array (e.g. 'uint256[50] private __gap;'). "
                    f"If a future upgrade adds state variables, it will cause storage collision in inheriting contracts."
                )

            # Mode 2: Proxy Construction Validation (State Variable Initializations Outside initialize())
            # We want to find state variable declarations with assignments that are:
            # - inside the contract body
            # - NOT inside a function or constructor
            # - NOT constants/immutable (since constants and immutables are stored in bytecode, not storage slot)
            # Let's search for assignments like `type name = value;`
            # Clean comments first in the contract body
            cleaned_body = re.sub(r"//.*", "", contract_body)
            cleaned_body = re.sub(r"/\*.*?\*/", "", cleaned_body, flags=re.DOTALL)

            # Find matches of "type [public/private/internal/external] name = value;"
            # Or simply look for '=' signs that are outside of function blocks
            lines = cleaned_body.split("\n")
            for _line_idx, line in enumerate(lines):
                line_clean = line.strip()
                if not line_clean or line_clean.startswith("*") or line_clean.startswith("//"):
                    continue
                # Match a variable declaration with initialization: e.g., "uint256 public x = 100;"
                # Must contain "=" and ";"
                if "=" in line_clean and ";" in line_clean:
                    # Ignore constant/immutable
                    if "constant" in line_clean or "immutable" in line_clean:
                        continue
                    # Check if this line occurs inside a function block
                    # To do this safely, we can map the line back to the absolute index in the original code,
                    # or do a simple check. Let's find the absolute index of this line in the code:
                    absolute_index = code.find(line_clean)
                    if absolute_index != -1 and not is_inside_function(code, absolute_index):
                        vulnerable_funcs.append(contract_name)
                        flagged_findings.append(
                            f"Upgradeable contract '{contract_name}' initializes state variable on line: '{line_clean}'. "
                            f"State variables initialized outside of the 'initialize()' function are ignored by proxy storage, "
                            f"causing the variable to remain uninitialized (default to 0/false) when called via a proxy."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_UPGRADE_RISK"
            else:
                status = "WARN_UPGRADE_RISK"
                is_secure = True

        return UpgradeDefectOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
