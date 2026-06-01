from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_DIRTY_MEMORY_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class DirtyMemoryInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class DirtyMemoryOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if memory safety checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed inline assembly memory safety findings"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_DIRTY_MEMORY, REJECTED_DIRTY_MEMORY)")


# 3. Core Micro-Agent Class
class PiSolidityDirtyMemorySentry:
    """Specialized Yul / inline assembly micro-agent that audits Solidity contracts for memory safety and dirty memory overwrites."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityDirtyMemorySentry"

    def audit_dirty_memory(self, input_envelope: DirtyMemoryInput) -> DirtyMemoryOutput:
        """Autonomously audits Solidity contracts for inline assembly memory safety violations."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            if "assembly" in body and "mstore" in body:
                # Check if it writes to dynamic memory offsets (above 0x80) without reading the free memory pointer (0x40)
                has_free_mem_load = "mload(0x40)" in body.replace(" ", "")

                # Check for direct writes above the scratch space / zero slot absolute boundary without free memory load
                # e.g., mstore(0x80, ...), mstore(128, ...)
                writes_absolute_dynamic = re.search(r"mstore\s*\(\s*(0x[89a-fA-F0-9]{2,}|1[2-9]\d|\d{3,})\s*,", body)

                if writes_absolute_dynamic and not has_free_mem_load:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' writes directly to absolute memory offset in assembly "
                        "without loading the Solidity free memory pointer via 'mload(0x40)'. "
                        "This violates Solidity's memory safety rules and can lead to dynamic memory corruption or overwriting active data struct layouts."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_DIRTY_MEMORY"
            else:
                status = "WARN_DIRTY_MEMORY"
                is_secure = True

        return DirtyMemoryOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
