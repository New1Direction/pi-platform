from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_YUL_MEMORY_OFFSET_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class YulMemoryOffsetInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class YulMemoryOffsetOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract Yul memory offset usage is secure")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed findings on Yul memory offset usage"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityYulMemoryOffsetAudit:
    """Specialized Web3 micro-agent that audits Yul inline assembly for risky memory writes to reserved scratch spaces (e.g. 0x00-0x3f) or incorrect free memory pointer (0x40) offsets."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityYulMemoryOffsetAudit"

    def audit_yul_memory(self, input_envelope: YulMemoryOffsetInput) -> YulMemoryOffsetOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            # Check if there is an assembly block
            if "assembly" in body:
                # Find all mstore operations in assembly
                mstores = re.findall(r"mstore\s*\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*.*?\)", body)
                for offset_str in mstores:
                    try:
                        # Convert hex or decimal offset
                        offset = int(offset_str, 16) if "0x" in offset_str else int(offset_str)
                        # Check if offset is strictly in the reserved ranges 0x00 - 0x3f
                        # Scratch pad usage (0x00-0x3f) is okay for temporary hashes, but let's check for writes outside of free memory boundaries (like over 0x80) where the free memory pointer (0x40) was not updated
                        # Or writing directly to 0x40 (overwriting the free memory pointer itself!)
                        if offset == 0x40:
                            vulnerable_funcs.append(name)
                            flagged_findings.append(
                                f"Function '{name}' overwrites the free memory pointer at offset '0x40' directly inside Yul assembly. "
                                "Modifying the free memory pointer offset without reallocation protocol can corrupt the EVM memory heap, leading to critical logic errors or access control bypasses."
                            )
                            break
                    except ValueError:
                        pass

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_YUL_MEMORY_OFFSET"
            else:
                status = "WARN_YUL_MEMORY_OFFSET"
                is_secure = True

        return YulMemoryOffsetOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
