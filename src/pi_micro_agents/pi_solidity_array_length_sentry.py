from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ARRAY_LENGTH_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_ARRAY_LENGTH_STRICT_MODE", True))
        except Exception:
            pass
    return True


class ArrayLengthInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class ArrayLengthOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Solidity array length checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityArrayLengthSentry:
    """Specialized Web3 micro-agent that audits Solidity dynamic array parameters to prevent block gas limit DoS via unbounded iteration loops."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityArrayLengthSentry"

    def audit_array_length(self, input_envelope: ArrayLengthInput) -> ArrayLengthOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all public/external functions
        func_blocks = re.findall(
            r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*(external|public)[\s\S]*?\{([\s\S]*?)(?=\n\s*function|\Z)",
            code,
        )

        for name, args, _visibility, body in func_blocks:
            # Check if there is an array parameter in signature
            array_matches = re.findall(r"([a-zA-Z0-9_]+)\[\]\s*(?:calldata|memory)?\s*([a-zA-Z0-9_]+)", args)
            if array_matches:
                for _arr_type, arr_name in array_matches:
                    # Check if there is a loop iterating up to this array's length
                    if rf"{arr_name}.length" in body:
                        # Look for limit checks on the array's length
                        # E.g. require(arr.length <= MAX_LIMIT, ...)
                        has_limit_check = False
                        if re.search(rf"require\s*\(\s*{arr_name}\.length\s*(<=|<)", body):
                            has_limit_check = True

                        if not has_limit_check:
                            vulnerable_funcs.append(name)
                            flagged_findings.append(
                                f"Function '{name}' processes dynamic array parameter '{arr_name}' "
                                f"and iterates over its length without enforcing a maximum limit check. "
                                f"An attacker or user could pass a massive array causing block gas limit exhaustion DoS."
                            )
                            break

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 70.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ARRAY_LENGTH"
            else:
                status = "WARN_ARRAY_LENGTH"
                is_secure = True

        return ArrayLengthOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
