from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_README_STRICT_MODE")


class ReadmeInput(BaseModel):
    readme_content: str = Field(..., description="Markdown content of the README file")


class ReadmeOutput(BaseModel):
    is_secure: bool = Field(..., description="True if all critical document sections are present")
    missing_sections: List[str] = Field(default_factory=list, description="List of missing section headers")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status of the audit")


class PiReadmeValidator:
    """Deterministic micro-agent that checks a README.md file for critical sections (Installation, Prerequisites, etc.)."""

    def __init__(self) -> None:
        self.agent_name = "PiReadmeValidator"

    def validate_readme(self, input_envelope: ReadmeInput) -> ReadmeOutput:
        content = input_envelope.readme_content
        missing_sections = []

        # Sections we expect to find in a complete README (case insensitive heading match)
        expected_sections = [
            ("prerequisites", [r"^#+\s+.*prerequisite", r"^#+\s+.*requirement"]),
            ("installation", [r"^#+\s+.*install"]),
            ("usage", [r"^#+\s+.*usage", r"^#+\s+.*getting\s+started"]),
        ]

        lines = content.splitlines()
        for section_name, patterns in expected_sections:
            found = False
            for line in lines:
                if any(re.search(pat, line, flags=re.IGNORECASE) for pat in patterns):
                    found = True
                    break
            if not found:
                missing_sections.append(section_name)

        is_secure = len(missing_sections) == 0
        risk_score = 40.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_README"
            else:
                status = "WARN_README"
                is_secure = True

        return ReadmeOutput(
            is_secure=is_secure, missing_sections=missing_sections, risk_score=risk_score, status=status
        )
