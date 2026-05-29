from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_TRANSIENT_STORAGE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_TRANSIENT_STORAGE_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class TransientStorageInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class TransientStorageOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract transient storage usage is secure")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed transient storage safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_TRANSIENT_RISK, REJECTED_TRANSIENT_RISK)")


# 3. Core Micro-Agent Class
class PiSolidityTransientStorageSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for Cancun EIP-1153 transient storage (tstore/tload) misuse."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityTransientStorageSentry"

    def audit_transient_storage(self, input_envelope: TransientStorageInput) -> TransientStorageOutput:
        """Autonomously audits Solidity contracts for tstore/tload safety in assembly blocks."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            # Look for assembly block containing tstore/tload
            if "assembly" in body and ("tstore" in body or "tload" in body):
                # Check if it has a tstore to clear the slot (tstore(slot, 0))
                has_clear = re.search(r"tstore\s*\(\s*[a-zA-Z0-9_]+\s*,\s*0\s*\)", body)
                if not has_clear:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' utilizes transient storage (tstore/tload) "
                        "but does not explicitly clear the storage slot to zero before exit. "
                        "This may lead to transient reentrancy and dirty state bugs across transaction calls."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_TRANSIENT_RISK"
            else:
                status = "WARN_TRANSIENT_RISK"
                is_secure = True

        return TransientStorageOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
