from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_GITHUB_ACTIONS_UNPINNED_STRICT_MODE")


class GithubActionsUnpinnedInput(BaseModel):
    file_path: str = Field(..., description="Github Action workflow file path")
    yaml_code: str = Field(..., description="Github Action workflow YAML content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class GithubActionsUnpinnedOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if all third-party actions are pinned to a commit SHA")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable lines or actions")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiGithubActionsUnpinnedVersion:
    """Specialized Infrastructure micro-agent that audits Github Action workflow steps for unpinned third-party actions."""

    def __init__(self) -> None:
        self.agent_name = "PiGithubActionsUnpinnedVersion"

    def audit_github_actions(self, input_envelope: GithubActionsUnpinnedInput) -> GithubActionsUnpinnedOutput:
        code = input_envelope.yaml_code
        vulnerable_elements = []
        flagged_findings = []

        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            # Look for lines containing "uses:"
            if clean_line.startswith("uses:") or "uses:" in clean_line:
                # Exclude local actions or official actions that are ignored, focus on third-party actions
                # Action usage format: uses: owner/repo@tagOrSha or owner/repo/path@tagOrSha
                match = re.search(r"uses:\s*([a-zA-Z0-9_\-\./]+)@([a-zA-Z0-9_\-\.]+)", clean_line)
                if match:
                    action_name = match.group(1)
                    ref = match.group(2)

                    # Ignore local actions (e.g. uses: ./.github/actions/something)
                    if action_name.startswith("./"):
                        continue

                    # Check if ref is a full 40-character hex commit SHA
                    is_sha = re.match(r"^[a-fA-F0-9]{40}$", ref)
                    if not is_sha:
                        vulnerable_elements.append(f"Line {idx}")
                        flagged_findings.append(
                            f"Line {idx}: Action '{action_name}' is pinned to tag or branch '{ref}' instead of a secure full commit SHA. "
                            "Unpinned action dependencies allow upstream maintainers or attackers modifying tags to execute arbitrary code in workflows."
                        )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 70.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_GITHUB_ACTIONS_UNPINNED"
            else:
                status = "WARN_GITHUB_ACTIONS_UNPINNED"
                is_secure = True

        return GithubActionsUnpinnedOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
