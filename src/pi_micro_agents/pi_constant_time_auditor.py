from __future__ import annotations
import os, json, re
from typing import List
from pydantic import BaseModel, Field

def is_strict_mode() -> bool:
    env_val = os.getenv("PI_CONSTANT_TIME_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True

class ConstantTimeInput(BaseModel):
    file_path: str = Field(..., description="Path to cryptographic code file")
    source_code: str = Field(..., description="Content of cryptographic file")
    secrets_context: List[str] = Field(default_factory=list, description="Variables containing private keys/secrets")

class ConstantTimeOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no variable-time operations found on secrets")
    flagged_lines: List[str] = Field(default_factory=list, description="Flagged lines containing division or branching on secrets")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_TIMING_RISK, REJECTED_TIMING_RISK)")

class PiConstantTimeAuditor:
    """Specialized cryptographic micro-agent mapping timing side-channel risks."""
    
    def __init__(self) -> None:
        self.agent_name = "PiConstantTimeAuditor"

    def audit_constant_time(self, input_envelope: ConstantTimeInput) -> ConstantTimeOutput:
        code = input_envelope.source_code
        secrets = input_envelope.secrets_context
        flagged_lines = []
        
        # Enumerate lines
        for idx, line in enumerate(code.splitlines(), 1):
            # Check for division / modulo on any known secret
            for secret in secrets:
                if secret in line:
                    if "/" in line or "%" in line:
                        flagged_lines.append(f"L{idx}: Potential secret-dependent division/modulo on '{secret}': {line.strip()}")
                    if re.search(r'\bif\s*\(.*' + re.escape(secret) + r'.*\)', line) or re.search(r'\bwhile\s*\(.*' + re.escape(secret) + r'.*\)', line):
                        flagged_lines.append(f"L{idx}: Potential secret-dependent branch/loop condition on '{secret}': {line.strip()}")

        is_secure = len(flagged_lines) == 0
        risk_score = 95.0 if not is_secure else 0.0
        
        status = "PASSED"
        if not is_secure:
            status = "REJECTED_TIMING_RISK" if is_strict_mode() else "WARN_TIMING_RISK"
            if not is_strict_mode():
                is_secure = True
                
        return ConstantTimeOutput(
            is_secure=is_secure,
            flagged_lines=flagged_lines,
            risk_score=risk_score,
            status=status
        )
