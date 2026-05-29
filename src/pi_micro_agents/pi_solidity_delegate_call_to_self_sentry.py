from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_DELEGATECALL_SELF_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_DELEGATECALL_SELF_STRICT_MODE", True))
        except Exception:
            pass
    return True


class DelegateCallSelfInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class DelegateCallSelfOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if delegatecall-to-self checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityDelegateCallToSelfSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for delegatecalls targeting address(this) or self-references."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityDelegateCallToSelfSentry"

    def audit_delegatecall_self(self, input_envelope: DelegateCallSelfInput) -> DelegateCallSelfOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions and search for self-delegatecalls
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)", code)

        for name, _args, body in func_blocks:
            is_vuln = False
            finding_msg = ""

            # Check Solidity delegatecall to address(this)
            solidity_match = re.search(r"(address\(\s*this\s*\)|this)\s*\.\s*delegatecall", body)
            if solidity_match:
                is_vuln = True
                finding_msg = (
                    f"Function '{name}' makes a direct high-level Solidity 'delegatecall' targeting "
                    f"'{solidity_match.group(1)}'. Self-delegatecall corrupts contract storage structures "
                    f"and opens vectors for total proxy destruction or privilege bypass."
                )

            # Check inline assembly delegatecall to address(this)
            assembly_match = re.search(r"delegatecall\s*\(\s*[^,]+,\s*(address\(\s*this\s*\)|this)\s*,", body)
            if assembly_match:
                is_vuln = True
                finding_msg = (
                    f"Function '{name}' contains inline assembly calling 'delegatecall' targeting "
                    f"'{assembly_match.group(1)}'. Self-delegatecall in assembly can corrupt free memory pointers "
                    f"and allow attackers to overwrite storage variables."
                )

            if is_vuln:
                vulnerable_funcs.append(name)
                flagged_findings.append(finding_msg)

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_DELEGATECALL_SELF"
            else:
                status = "WARN_DELEGATECALL_SELF"
                is_secure = True

        return DelegateCallSelfOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
