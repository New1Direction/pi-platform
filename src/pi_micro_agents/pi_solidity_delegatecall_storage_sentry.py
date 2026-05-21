from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_DELEGATECALL_STORAGE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_DELEGATECALL_STORAGE_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class DelegatecallStorageInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class DelegatecallStorageOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if delegatecall storage checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed proxy delegatecall storage safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_DELEGATECALL_STORAGE, REJECTED_DELEGATECALL_STORAGE)")


# 3. Core Micro-Agent Class
class PiSolidityDelegatecallStorageSentry:
    """Specialized Web3 micro-agent that audits proxy contracts for Yul delegatecall EIP-1967 storage compliance."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityDelegatecallStorageSentry"

    def audit_delegatecall_storage(self, input_envelope: DelegatecallStorageInput) -> DelegatecallStorageOutput:
        """Autonomously audits proxy delegatecall implementations for safe storage layout target loads."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        for name, args, body in func_blocks:
            # Check if delegatecall is used inside assembly
            if "assembly" in body and "delegatecall" in body:
                # Look for target loaded using sload
                sload_match = re.search(r'sload\s*\(\s*(0x[a-fA-F0-9]+|[a-zA-Z0-9_]+)\s*\)', body)
                if sload_match:
                    slot = sload_match.group(1)
                    # Check if slot is an EIP-1967 slot constant
                    # Implementation slot: 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc
                    # Beacon slot: 0xa3f0ad74a5890d8e115a428731304671291891c9d44342144a0b228226348149
                    # Admin slot: 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
                    eip1967_slots = [
                        "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
                        "0xa3f0ad74a5890d8e115a428731304671291891c9d44342144a0b228226348149",
                        "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
                    ]
                    if slot not in eip1967_slots:
                        vulnerable_funcs.append(name)
                        flagged_findings.append(
                            f"Function '{name}' performs a delegatecall where the target implementation "
                            f"address is loaded from non-standard storage slot '{slot}'. "
                            "Proxy implementation targets should be saved in standard EIP-1967 constant slots "
                            "to mitigate the risk of storage layout collision and unintended state overwrites."
                        )
                else:
                    # delegatecall used without apparent slot verification
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' contains a delegatecall instruction in inline assembly but "
                        "does not show clear EIP-1967 storage slot loading patterns for the implementation target."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_DELEGATECALL_STORAGE"
            else:
                status = "WARN_DELEGATECALL_STORAGE"
                is_secure = True

        return DelegatecallStorageOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
