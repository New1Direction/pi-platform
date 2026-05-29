from __future__ import annotations

import os
import re
from typing import Any, Dict, List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_TO_ISSUES_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class ToIssuesInput(BaseModel):
    spec_content: str = Field(..., description="Markdown planning specification")


class ToIssuesOutput(BaseModel):
    is_secure: bool = Field(..., description="True if parsing succeeded and issues are structured")
    issues: List[Dict[str, Any]] = Field(default_factory=list, description="Parsed task/issue items")
    parsing_errors: List[str] = Field(default_factory=list, description="Any missing details in tasks")
    risk_score: float = Field(..., description="Calculated risk score")
    status: str = Field(..., description="Status (PASSED, REJECTED_TO_ISSUES, WARN_TO_ISSUES)")


class PiToIssuesBreakdown:
    """Deterministic micro-agent that parses specs into discrete, grabbable issue structures."""

    def __init__(self) -> None:
        self.agent_name = "PiToIssuesBreakdown"

    def breakdown_issues(self, input_envelope: ToIssuesInput) -> ToIssuesOutput:
        spec = input_envelope.spec_content
        issues = []
        errors = []

        # Check for acceptance criteria
        if "acceptance criteria" not in spec.lower() and "criteria" not in spec.lower():
            errors.append("Missing acceptance criteria in the specification.")

        # Parse list items like: - [ ] Task Name or - Task Name or Task 1: Name
        task_patterns = [r"\bTask\s+\d+:\s*([^\.]+)", r"-\s*\[\s*\]\s*([^\.]+)", r"-\s+([a-zA-Z0-9_\s]+)"]

        seen_titles = set()
        for pat in task_patterns:
            for m in re.finditer(pat, spec):
                task_text = m.group(1).strip()
                if (
                    task_text
                    and task_text.lower() not in ["checklist", "acceptance criteria"]
                    and task_text not in seen_titles
                ):
                    seen_titles.add(task_text)
                    issues.append(
                        {
                            "id": f"issue_{len(issues) + 1}",
                            "title": task_text,
                            "description": f"Extracted task: {task_text}",
                        }
                    )

        if not issues and spec.strip():
            errors.append("No structured checklist items found in the planning specification.")

        is_secure = len(errors) == 0
        risk_score = 75.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_TO_ISSUES"
            else:
                status = "WARN_TO_ISSUES"
                is_secure = True

        return ToIssuesOutput(
            is_secure=is_secure, issues=issues, parsing_errors=errors, risk_score=risk_score, status=status
        )
