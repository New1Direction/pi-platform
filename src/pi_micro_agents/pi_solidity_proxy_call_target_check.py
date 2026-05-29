from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_PROXY_CALL_TARGET_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class ProxyCallTargetInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ProxyCallTargetOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract proxy call targets are secure")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed findings on proxy call target risks"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityProxyCallTargetCheck:
    """Specialized Web3 micro-agent that audits upgradeable proxy contracts to ensure delegatecall targets are validated against a whitelist/storage slot, rather than arbitrary user-supplied parameters."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityProxyCallTargetCheck"

    def audit_proxy_target(self, input_envelope: ProxyCallTargetInput) -> ProxyCallTargetOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, args, body in func_blocks:
            # Check for delegatecall usage
            if "delegatecall" in body:
                # Look for delegatecall(..., target, ...) inside assembly or target.delegatecall(...)
                # Check if the target parameter is passed as a function argument
                is_arg_target = False
                arg_names = [arg.strip().split()[-1] for arg in args.split(",") if len(arg.strip().split()) >= 2]

                # Check if delegatecall uses any function argument directly as the target
                for arg_name in arg_names:
                    if re.search(r"\bdelegatecall\s*\([^)]*?\b" + re.escape(arg_name) + r"\b", body) or re.search(
                        r"\b" + re.escape(arg_name) + r"\.delegatecall\b", body
                    ):
                        is_arg_target = True
                        break

                # If the target is an argument, verify it has a whitelist or mapping check
                if is_arg_target:
                    has_whitelist_check = any(
                        kw in body for kw in ["whitelist", "isTarget", "isWhitelisted", "require", "assert"]
                    )
                    if not has_whitelist_check:
                        vulnerable_funcs.append(name)
                        flagged_findings.append(
                            f"Function '{name}' performs a delegatecall where the target is a user-supplied parameter, but no whitelist validation was found. "
                            "This allows an attacker to pass a malicious contract address as the target, seizing complete administrative control of the proxy storage state."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_PROXY_CALL_TARGET"
            else:
                status = "WARN_PROXY_CALL_TARGET"
                is_secure = True

        return ProxyCallTargetOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
