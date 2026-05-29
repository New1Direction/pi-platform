from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ASSEMBLY_MEMORY_SAFE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_ASSEMBLY_MEMORY_SAFE_STRICT_MODE", True))
        except Exception:
            pass
    return True


class AssemblyMemorySafeInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class AssemblyMemorySafeOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if assembly memory-safe checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityAssemblyMemorySafeSentry:
    """Specialized Web3 micro-agent that audits assembly blocks marked as memory-safe to ensure they don't corrupt scratchpad or pre-0x80 memory offsets."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityAssemblyMemorySafeSentry"

    def audit_assembly_memory_safe(self, input_envelope: AssemblyMemorySafeInput) -> AssemblyMemorySafeOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions containing assembly blocks
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)", code)

        for name, _args, body in func_blocks:
            # Check if there is an assembly "memory-safe" marker
            assembly_safe_match = re.search(r'assembly\s*\(\s*["\']memory-safe["\']\s*\)\s*\{([\s\S]*?)\}', body)
            if assembly_safe_match:
                assembly_body = assembly_safe_match.group(1)

                # Look for mstore or mload targeting scratch spaces (< 0x80)
                # E.g. mstore(0x0, ...), mstore(0x20, ...), mstore(0x40, ...)
                # (Note that 0x00-0x3f is scratch space, 0x40-0x5f is free memory pointer, 0x60-0x7f is zero slot)
                # If they write below 0x80 (128 bytes) using mstore or mstore8:
                mstore_match = re.search(r"mstore(8)?\s*\(\s*(0x[0-7][0-9a-fA-F]?|[0-9]+)\s*,", assembly_body)
                if mstore_match:
                    offset_str = mstore_match.group(2)
                    try:
                        offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                    except ValueError:
                        offset = 128  # Safe default if parsing fails

                    if offset < 128:  # less than 0x80
                        vulnerable_funcs.append(name)
                        flagged_findings.append(
                            f"Function '{name}' contains an assembly block explicitly marked as 'memory-safe' "
                            f"but performs 'mstore' to memory offset '{offset_str}' (< 0x80). Writing below 0x80 "
                            f"corrupts scratchpad memory, the free memory pointer, or the zero slot, violating Solidity's "
                            f"memory safety assumptions."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ASSEMBLY_MEMORY_SAFE"
            else:
                status = "WARN_ASSEMBLY_MEMORY_SAFE"
                is_secure = True

        return AssemblyMemorySafeOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
