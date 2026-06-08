from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ARBITRARY_TRANSFER_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class ArbitraryTransferInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class ArbitraryTransferOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if arbitrary transfer checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed arbitrary transfer safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_ARBITRARY_TRANSFER, REJECTED_ARBITRARY_TRANSFER)"
    )


# 3. Core Micro-Agent Class
class PiSolidityArbitraryTransferSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for unsafe arbitrary ERC-20 token transfers without whitelist gates."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityArbitraryTransferSentry"

    def audit_arbitrary_transfer(self, input_envelope: ArbitraryTransferInput) -> ArbitraryTransferOutput:
        """Autonomously audits Solidity contracts for arbitrary transfer/transferFrom patterns on user-supplied addresses."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, args, body in func_blocks:
            # Check if function takes an address parameter that might represent a token
            param_matches = re.findall(r"address\s+([a-zA-Z0-9_]+)", args)
            if not param_matches:
                continue

            for param in param_matches:
                # Look for transfer / transferFrom called on this parameter
                # e.g., token.transfer, IERC20(token).transfer, SafeERC20.safeTransfer(token, ...) or token.safeTransfer
                is_transferred = (
                    re.search(rf"{param}\s*\.\s*(?:transfer|transferFrom|safeTransfer)", body)
                    or re.search(rf"IERC20\s*\(\s*{param}\s*\)\s*\.\s*(?:transfer|transferFrom|safeTransfer)", body)
                    or re.search(rf"safeTransfer\s*\(\s*(?:IERC20\s*\()?\s*{param}\s*\)?", body)
                )

                if is_transferred:
                    # Check if there is a whitelist check or dynamic parameter validation matching this parameter
                    # e.g. whitelist[param], isWhitelisted[param], require(param == trustedToken)
                    has_whitelist_check = (
                        re.search(rf"whitelist\s*\[\s*{param}\s*\]", body)
                        or re.search(rf"isWhitelisted\s*\[\s*{param}\s*\]", body)
                        or re.search(rf"require\s*\(\s*{param}\s*==\s*[a-zA-Z0-9_]+\s*\)", body)
                        or re.search(rf"require\s*\(\s*[a-zA-Z0-9_]+\s*==\s*{param}\s*\)", body)
                        or "onlyOwner" in body
                        or "onlyAdmin" in body
                    )

                    if not has_whitelist_check:
                        vulnerable_funcs.append(name)
                        flagged_findings.append(
                            f"Function '{name}' accepts a user-controlled token address '{param}' "
                            "and triggers a transfer or transferFrom operation without performing whitelist verification. "
                            "This could allow attackers to call malicious tokens or siphon approved assets."
                        )
                        break

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ARBITRARY_TRANSFER"
            else:
                status = "WARN_ARBITRARY_TRANSFER"
                is_secure = True

        return ArbitraryTransferOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
