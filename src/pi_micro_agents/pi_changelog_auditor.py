from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_CHANGELOG_STRICT_MODE")


class ChangelogInput(BaseModel):
    changelog_content: str = Field(..., description="Markdown content of the CHANGELOG file")
    target_version: str = Field(..., description="Version identifier to verify exists (e.g., '1.2.3' or 'v1.2.3')")


class ChangelogOutput(BaseModel):
    is_secure: bool = Field(..., description="True if target version entry is found and correctly formatted")
    format_issues: List[str] = Field(
        default_factory=list, description="List of formatting issues or missing entries found"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status of the audit")


class PiChangelogAuditor:
    """Deterministic micro-agent that verifies the target version's CHANGELOG.md entry structure."""

    def __init__(self) -> None:
        self.agent_name = "PiChangelogAuditor"

    def audit_changelog(self, input_envelope: ChangelogInput) -> ChangelogOutput:
        content = input_envelope.changelog_content
        version = input_envelope.target_version.strip().lstrip("v")
        issues = []

        # Look for headers containing the version, e.g., '## [1.2.3]', '## v1.2.3', '## 1.2.3'
        escaped_version = re.escape(version)
        version_header_pattern = rf"^##\s+\[?v?{escaped_version}\]?"

        lines = content.splitlines()
        found_version_header = False
        version_header_line_idx = -1

        for idx, line in enumerate(lines):
            if re.search(version_header_pattern, line):
                found_version_header = True
                version_header_line_idx = idx
                break

        if not found_version_header:
            issues.append(f"Target version '{input_envelope.target_version}' entry not found in CHANGELOG")
        else:
            # Check if there are descriptive bullet points below the target version header
            # and before the next major section (any line starting with '##')
            bullet_points_found = False
            for idx in range(version_header_line_idx + 1, len(lines)):
                line = lines[idx].strip()
                if line.startswith("##"):
                    break
                if line.startswith("-") or line.startswith("*") or re.match(r"^\d+\.", line):
                    bullet_points_found = True
                    break

            if not bullet_points_found:
                issues.append(
                    f"No release notes/bullet points found under target version '{input_envelope.target_version}' header"
                )

        is_secure = len(issues) == 0
        risk_score = 45.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_CHANGELOG"
            else:
                status = "WARN_CHANGELOG"
                is_secure = True

        return ChangelogOutput(is_secure=is_secure, format_issues=issues, risk_score=risk_score, status=status)
