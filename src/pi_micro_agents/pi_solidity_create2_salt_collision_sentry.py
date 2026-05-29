from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_CREATE2_SALT_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_CREATE2_SALT_STRICT_MODE", True))
        except Exception:
            pass
    return True


class Create2SaltCollisionInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class Create2SaltCollisionOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if CREATE2 salt collision checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityCreate2SaltCollisionSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for CREATE2 salt predictability and address hijacking risks."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityCreate2SaltCollisionSentry"

    def audit_create2_salt(self, input_envelope: Create2SaltCollisionInput) -> Create2SaltCollisionOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions containing CREATE2 deployments
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)", code)

        for name, _args, body in func_blocks:
            # Check for new Contract{salt: salt_var}(...) or create2(v, o, s, salt_var)
            has_create2 = False
            salt_var = ""

            # Check new Contract{salt: ...}
            new_salt_match = re.search(r"new\s+[a-zA-Z0-9_]+\s*\{\s*salt\s*:\s*([^}]+)\s*\}", body)
            if new_salt_match:
                has_create2 = True
                salt_var = new_salt_match.group(1).strip()

            # Check Yul create2
            yul_create2_match = re.search(r"create2\s*\(\s*[^,]+,\s*[^,]+,\s*[^,]+,\s*([^)]+)\)", body)
            if yul_create2_match:
                has_create2 = True
                salt_var = yul_create2_match.group(1).strip()

            if has_create2:
                # Analyze if salt incorporates msg.sender (either directly, or msg.sender is hashed via keccak256)
                # Look for msg.sender in the function body or specifically as part of the salt variable's calculation
                if "msg.sender" not in body:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' executes a deterministic CREATE2 deployment using salt '{salt_var}' "
                        f"but does not incorporate 'msg.sender' in the salt calculation. Predictable or user-controlled "
                        f"salts without caller-based entropy are vulnerable to front-running address hijacking."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_CREATE2_SALT"
            else:
                status = "WARN_CREATE2_SALT"
                is_secure = True

        return Create2SaltCollisionOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
