from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_TRANSFER_RECIPIENT_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_TRANSFER_RECIPIENT_STRICT_MODE", True))
        except Exception:
            pass
    return True


class ERC20TransferRecipientInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class ERC20TransferRecipientOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if token transfer recipient checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityERC20TransferRecipientSentry:
    """Specialized Web3 micro-agent that audits Solidity code to ensure ERC20 transfers validate the target recipient address to prevent lost funds."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityERC20TransferRecipientSentry"

    def audit_transfer_recipient(self, input_envelope: ERC20TransferRecipientInput) -> ERC20TransferRecipientOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions performing transfer or transferFrom calls
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)", code)

        for name, _args, body in func_blocks:
            # Match transfers: e.g. token.transfer(recipient, amount) or token.transferFrom(sender, recipient, amount)
            transfers = re.findall(r"\.\s*(transfer|transferFrom)\s*\(([^)]+)\)", body)
            if transfers:
                for method, params in transfers:
                    # Extract recipient param (the first parameter for transfer, second for transferFrom)
                    param_list = [p.strip() for p in params.split(",")]
                    if len(param_list) > 0:
                        recipient = (
                            param_list[0] if method == "transfer" else (param_list[1] if len(param_list) > 1 else "")
                        )
                        if recipient:
                            # Check if body contains validations for this recipient address
                            # E.g. require(recipient != address(0), ...) or require(recipient != address(this), ...)
                            has_validation = False
                            # Look for require/assert checking the recipient against address(0), address(this), etc.
                            patterns = [r"address\s*\(\s*0\s*\)", r"address\s*\(\s*this\s*\)", r"0x0"]
                            for pat in patterns:
                                if re.search(rf"require\s*\(\s*{recipient}\s*!=\s*{pat}", body) or re.search(
                                    rf"require\s*\(\s*{pat}\s*!=\s*{recipient}", body
                                ):
                                    has_validation = True
                                    break

                            if not has_validation:
                                vulnerable_funcs.append(name)
                                flagged_findings.append(
                                    f"Function '{name}' performs a token '{method}' to recipient '{recipient}' "
                                    f"without validating the recipient is not address(0), address(this), or a blacklisted "
                                    f"dead address. This can cause locked or burned user tokens."
                                )
                                break

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 65.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_TRANSFER_RECIPIENT"
            else:
                status = "WARN_TRANSFER_RECIPIENT"
                is_secure = True

        return ERC20TransferRecipientOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
