from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_L2_GAS_FEE_STRICT_MODE")


class L2GasFeeInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class L2GasFeeOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if L2 gas fee checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityL2GasFeeSentry:
    """Specialized Web3 micro-agent that audits Solidity code to ensure Layer-2 gas fee and calldata optimizations are followed."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityL2GasFeeSentry"

    def audit_l2_gas_fee(self, input_envelope: L2GasFeeInput) -> L2GasFeeOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all public/external function definitions
        func_blocks = re.findall(
            r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*(external|public)[\s\S]*?\{([\s\S]*?)(?=\n\s*function|\Z)",
            code,
        )

        for name, args, _visibility, body in func_blocks:
            # Check for dynamic array or bytes parameters in arguments
            if "[]" in args or "bytes" in args:
                # Look for length limit validation in the body
                # E.g. require(arg.length <= MAX) or if (arg.length > MAX) revert
                has_length_check = False
                # Simple heuristic: find if .length is checked against a number or variable
                if re.search(r"\.length\s*(<=|<|>|>=|==|!=)", body):
                    has_length_check = True

                if not has_length_check:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' accepts a dynamic calldata/memory parameter in its signature "
                        f"but does not enforce a maximum length boundary on the input. On L2 deployments, "
                        f"unbounded calldata size creates high L1 data fee exposure and potential out-of-gas DoS."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 70.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_L2_GAS_FEE"
            else:
                status = "WARN_L2_GAS_FEE"
                is_secure = True

        return L2GasFeeOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
