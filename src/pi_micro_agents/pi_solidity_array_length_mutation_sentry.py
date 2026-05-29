from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ARRAY_LENGTH_MUTATION_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class ArrayLengthMutationInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ArrayLengthMutationOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract array length mutations are secure")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on array length mutations")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityArrayLengthMutationSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for unsafe inline assembly or direct manual mutations of array lengths."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityArrayLengthMutationSentry"

    def audit_array_length_mutation(self, input_envelope: ArrayLengthMutationInput) -> ArrayLengthMutationOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            # Look for assembly block modifying array length (e.g. sstore(..., length) or assembly mutating length slot)
            # Or manually changing .length (e.g. arr.length = newLength or arr.length--)
            has_assembly_mutation = "assembly" in body and ("sstore" in body) and ("length" in body or "len" in body)
            has_direct_length_assignment = re.search(r"\.[a-zA-Z0-9_]+\.length\s*[-+=\/]?=", body)

            if has_assembly_mutation or has_direct_length_assignment:
                vulnerable_funcs.append(name)
                flagged_findings.append(
                    f"Function '{name}' modifies the length of an array directly or inside assembly. "
                    "Manually mutating array lengths can bypass array boundary checks, leading to out-of-bounds storage corruption or memory overflow exploits."
                )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ARRAY_LENGTH_MUTATION"
            else:
                status = "WARN_ARRAY_LENGTH_MUTATION"
                is_secure = True

        return ArrayLengthMutationOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
