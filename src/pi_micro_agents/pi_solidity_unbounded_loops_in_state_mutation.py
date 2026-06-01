from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_UNBOUNDED_LOOPS_STATE_STRICT_MODE")


class UnboundedLoopsStateInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class UnboundedLoopsStateOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract unbounded loop mutations are secure")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed findings on unbounded loops with state updates"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityUnboundedLoopsInStateMutation:
    """Specialized Web3 micro-agent that audits contracts to detect state variable updates occurring inside unbounded for/while loops."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityUnboundedLoopsInStateMutation"

    def audit_unbounded_loops(self, input_envelope: UnboundedLoopsStateInput) -> UnboundedLoopsStateOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions using balanced brace matching to support nested blocks
        func_blocks = []
        for match in re.finditer(r"\bfunction\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{", code):
            name = match.group(1)
            args = match.group(2)
            start_idx = match.end()
            brace_count = 1
            idx = start_idx
            while idx < len(code) and brace_count > 0:
                char = code[idx]
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                idx += 1
            if brace_count == 0:
                body = code[start_idx : idx - 1]
                func_blocks.append((name, args, body))

        for name, _args, body in func_blocks:
            # Find loops (for or while)
            # e.g., for(uint i = 0; i < arr.length; i++) or for(uint i = 0; i < limit; i++)
            loops = re.findall(r"(for\s*\(.*?;(.*?);.*?\)|while\s*\(.*?\))", body)
            for loop_str, condition in loops:
                # Unbounded condition usually references array length or a parameter/variable, not a literal number
                cond_clean = re.sub(r"\b(i|j|k|index|iter)\b", "", condition) if condition else ""
                vars_in_cond = re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", cond_clean)
                is_unbounded = False
                if not condition:
                    is_unbounded = True
                elif len(vars_in_cond) > 0:
                    for var in vars_in_cond:
                        if var == "length":
                            is_unbounded = True
                            break
                        validation_pattern = r"\b(require|assert|if)\b[\s\S]*?\b" + re.escape(var) + r"\b"
                        if not re.search(validation_pattern, body):
                            is_unbounded = True
                            break
                if is_unbounded:
                    # Check for state mutation inside this loop
                    # State mutation indicators: storage writes, modifying external addresses, assignments like x = y or arr.push
                    # To simplify, look for assignment operators (=, +=, -=) on non-loop indices or state-like keywords
                    has_mutation = False
                    # Extract loop body
                    loop_body_match = re.search(re.escape(loop_str) + r"\s*\{([\s\S]*?)\}", body)
                    if loop_body_match:
                        loop_body = loop_body_match.group(1)
                        # Detect any assignment that is NOT the loop index (assuming standard loop indices are i, j, k)
                        assignments = re.findall(
                            r"\b([a-zA-Z0-9_]+)(?:\s*\[.*?\]|\s*\.[a-zA-Z0-9_]+)*\s*[-+*\/]?=(?!=)", loop_body
                        )
                        non_loop_assignments = [
                            asg for asg in assignments if asg.strip() not in ["i", "j", "k", "index", "iter"]
                        ]

                        if len(non_loop_assignments) > 0 or "sstore" in loop_body or ".push" in loop_body:
                            has_mutation = True

                    if has_mutation:
                        vulnerable_funcs.append(name)
                        flagged_findings.append(
                            f"Function '{name}' modifies state variables or performs storage modifications inside an unbounded loop. "
                            "If the loop boundary grows large, the transaction can exceed the block gas limit, causing a persistent Denial of Service (DoS)."
                        )
                        break

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_UNBOUNDED_LOOPS_STATE"
            else:
                status = "WARN_UNBOUNDED_LOOPS_STATE"
                is_secure = True

        return UnboundedLoopsStateOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
