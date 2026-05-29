from __future__ import annotations
import os, json, re
from typing import List
from pydantic import BaseModel, Field

def is_strict_mode() -> bool:
    env_val = os.getenv("PI_AGENT_GUARD_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True

class AgentToolGuardInput(BaseModel):
    command_string: str = Field(..., description="Proposed terminal shell command line")
    allowed_commands: List[str] = Field(default_factory=lambda: ["git", "pytest", "ruff", "python"], description="Prefixes of allowed commands")

class AgentToolGuardOutput(BaseModel):
    is_secure: bool = Field(..., description="True if command is safe to execute")
    blocked_patterns: List[str] = Field(default_factory=list, description="Banned elements or operators found")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status (PASSED, WARN_AGENT_RISK, REJECTED_AGENT_RISK)")

class PiAgentToolExecutionGuard:
    """Specialized dual-use runtime agentic guardrail linter."""

    def __init__(self) -> None:
        self.agent_name = "PiAgentToolExecutionGuard"

    def audit_agent_command(self, input_envelope: AgentToolGuardInput) -> AgentToolGuardOutput:
        cmd = input_envelope.command_string.strip()
        allowed = input_envelope.allowed_commands
        blocked = []

        # 1. Banned command elements (destructive or uncontrolled)
        banned_tokens = [r'\brm\b\s+-rf', r'\bsh\b\s+-[c]?', r'\bcurl\b\s+.*\|\s*sh', r'>\s*/dev/sda', r'\bchmod\b\s+777']
        for pat in banned_tokens:
            if re.search(pat, cmd):
                blocked.append(f"Highly destructive command pattern match: '{pat}'")

        # 2. Verify command starts with a whitelisted utility prefix
        tokens = cmd.split()
        if tokens:
            base_cmd = tokens[0]
            if base_cmd not in allowed and not any(cmd.startswith(a) for a in allowed):
                blocked.append(f"Command execution of base utility '{base_cmd}' is not in the whitelist.")

        is_secure = len(blocked) == 0
        risk_score = 100.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            status = "REJECTED_AGENT_RISK" if is_strict_mode() else "WARN_AGENT_RISK"
            if not is_strict_mode():
                is_secure = True

        return AgentToolGuardOutput(
            is_secure=is_secure,
            blocked_patterns=blocked,
            risk_score=risk_score,
            status=status
        )
