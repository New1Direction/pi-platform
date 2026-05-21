from __future__ import annotations
import os
import re
from typing import List
from pydantic import BaseModel, Field

def is_strict_mode() -> bool:
    env_val = os.getenv("PI_COMMIT_LINTER_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True

class CommitLinterInput(BaseModel):
    commit_message: str = Field(..., description="Commit message to audit")

class CommitLinterOutput(BaseModel):
    is_secure: bool = Field(..., description="True if the commit message conforms to Conventional Commits standards")
    formatting_errors: List[str] = Field(default_factory=list, description="List of lint/formatting errors found")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status of the audit")

class PiSemanticCommitMessageLinter:
    """Deterministic micro-agent that audits commit messages against Conventional Commits specification."""

    def __init__(self) -> None:
        self.agent_name = "PiSemanticCommitMessageLinter"

    def audit_commit_message(self, input_envelope: CommitLinterInput) -> CommitLinterOutput:
        msg = input_envelope.commit_message.strip()
        errors = []

        if not msg:
            errors.append("Commit message cannot be empty")
        else:
            # Match conventional commit pattern:
            # type(scope)!: description
            # E.g., feat(parser): add something
            # E.g., fix!: critical issue
            pattern = r"^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(?:\([a-zA-Z0-9_\-\/ ]+\))?(!)?:\s+(.+)$"
            match = re.match(pattern, msg)
            if not match:
                errors.append(
                    "Commit message does not match Conventional Commits format. "
                    "Expected: '<type>(<scope>): <description>' or '<type>: <description>'. "
                    "Allowed types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert"
                )
            else:
                description = match.group(3)
                if len(description) < 5:
                    errors.append("Commit description is too short (must be at least 5 characters)")

        is_secure = len(errors) == 0
        risk_score = 50.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_COMMIT_LINTER"
            else:
                status = "WARN_COMMIT_LINTER"
                is_secure = True

        return CommitLinterOutput(
            is_secure=is_secure,
            formatting_errors=errors,
            risk_score=risk_score,
            status=status
        )
