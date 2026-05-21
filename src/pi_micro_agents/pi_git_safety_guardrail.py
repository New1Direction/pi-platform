from __future__ import annotations
import os
import re
from typing import List
from pydantic import BaseModel, Field

def is_strict_mode() -> bool:
    env_val = os.getenv("PI_GIT_SAFETY_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True

class GitSafetyInput(BaseModel):
    command_string: str = Field(..., description="Proposed terminal shell command line")

class GitSafetyOutput(BaseModel):
    is_secure: bool = Field(..., description="True if command does not contain dangerous git flags")
    blocked_commands: List[str] = Field(default_factory=list, description="Blocked git elements found")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status (PASSED, REJECTED_GIT_SAFETY, WARN_GIT_SAFETY)")

class PiGitSafetyGuardrail:
    """Deterministic micro-agent that intercepts hazardous git command actions."""

    def __init__(self) -> None:
        self.agent_name = "PiGitSafetyGuardrail"

    def check_git_safety(self, input_envelope: GitSafetyInput) -> GitSafetyOutput:
        cmd = input_envelope.command_string.strip()
        blocked = []
        
        # Identify dangerous patterns
        dangerous_patterns = [
            (r"\bgit\b.*\bpush\b.*(?:\s-f\b|--force)", "push --force"),
            (r"\bgit\b.*\bbranch\b.*\s-D\b", "branch -D"),
            (r"\bgit\b.*\breset\b.*--hard", "reset --hard")
        ]
        
        for pat, desc in dangerous_patterns:
            if re.search(pat, cmd, flags=re.IGNORECASE):
                blocked.append(desc)
                
        is_secure = len(blocked) == 0
        risk_score = 100.0 if not is_secure else 0.0
        
        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_GIT_SAFETY"
            else:
                status = "WARN_GIT_SAFETY"
                is_secure = True
                
        return GitSafetyOutput(
            is_secure=is_secure,
            blocked_commands=blocked,
            risk_score=risk_score,
            status=status
        )
