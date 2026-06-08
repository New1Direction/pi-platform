from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_TRANSIENT_REENTRANCY_STRICT_MODE")


class TransientStorageReentrancyInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class TransientStorageReentrancyOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if transient storage checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityTransientStorageReentrancySentry:
    """Specialized Web3 micro-agent that audits Solidity code to ensure transient storage is explicitly cleared, preventing transient reentrancy."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityTransientStorageReentrancySentry"

    def audit_transient_reentrancy(
        self, input_envelope: TransientStorageReentrancyInput
    ) -> TransientStorageReentrancyOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all function definitions in Solidity
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)", code)

        for name, _args, body in func_blocks:
            # Check for transient store calls (tstore in assembly)
            tstore_calls = re.findall(r"tstore\s*\(\s*([^,)]+)\s*,\s*([^)]+)\)", body)
            if tstore_calls:
                # Check if there is an explicit clearing call (e.g. tstore(slot, 0))
                cleared = False
                for _slot, val in tstore_calls:
                    val_clean = val.strip()
                    if val_clean == "0" or val_clean == "0x0":
                        cleared = True
                        break

                if not cleared:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' utilizes transient storage ('tstore') but lacks a corresponding clear command "
                        f"reseting the slot to 0 before the execution completes. This leaves the contract vulnerable "
                        f"to transient storage reentrancy exploits."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_TRANSIENT_REENTRANCY"
            else:
                status = "WARN_TRANSIENT_REENTRANCY"
                is_secure = True

        return TransientStorageReentrancyOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
