from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_GCPPROJECTIDVALIDATOR_STRICT_MODE")


# GCP project IDs that look like reserved/generic environment names
_GENERIC_NAMES = {"test", "demo", "dev", "prod", "staging"}


class GCPProjectIDInput(BaseModel):
    project_id: str = Field(..., description="GCP project ID string to validate")
    strict_naming: bool = Field(
        default=True,
        description="When True, apply convention warnings for generic environment-like names",
    )


class GCPProjectIDOutput(BaseModel):
    is_valid: bool = Field(..., description="True if the project_id passes all structural rules")
    length: int = Field(..., description="Character length of the supplied project_id")
    issues: List[str] = Field(default_factory=list, description="List of structural violations and naming warnings")
    risk_score: float = Field(..., description="Risk score from 0.0 (no risk) to 100.0 (maximum risk)")
    status: str = Field(..., description="Validation status: PASS, WARN, or FAIL")


class PiGCPProjectIDValidator:
    """Validates a GCP project ID against Google Cloud naming rules and naming conventions."""

    def __init__(self) -> None:
        self.agent_name = "PiGCPProjectIDValidator"

    def execute(self, input_envelope: GCPProjectIDInput) -> GCPProjectIDOutput:
        """Validate a GCP project ID for length, character, and structural constraints.

        Args:
            input_envelope: Contains the project_id string and strict_naming flag.

        Returns:
            A GCPProjectIDOutput with validity, issues, risk score, and status.
        """
        project_id = input_envelope.project_id
        strict_naming = input_envelope.strict_naming

        issues: List[str] = []
        risk_score: float = 0.0
        length = len(project_id)

        # --- Length check: 6-30 chars ---
        if length < 6:
            issues.append(f"Project ID is too short ({length} chars). Minimum length is 6 characters.")
            risk_score += 25.0
        elif length > 30:
            issues.append(f"Project ID is too long ({length} chars). Maximum length is 30 characters.")
            risk_score += 25.0

        # --- Must start with a lowercase letter ---
        if project_id and not re.match(r"^[a-z]", project_id):
            issues.append(f"Project ID must start with a lowercase letter [a-z]. Got: '{project_id[0]}'.")
            risk_score += 25.0

        # --- Only [a-z0-9-] allowed ---
        invalid_chars = set(re.findall(r"[^a-z0-9\-]", project_id))
        if invalid_chars:
            issues.append(
                f"Project ID contains invalid character(s): "
                f"{', '.join(sorted(repr(c) for c in invalid_chars))}. "
                "Only lowercase letters, digits, and hyphens are allowed."
            )
            risk_score += 25.0

        # --- No consecutive hyphens ---
        if "--" in project_id:
            issues.append("Project ID must not contain consecutive hyphens ('--').")
            risk_score += 25.0

        # --- No leading hyphens ---
        if project_id.startswith("-"):
            issues.append("Project ID must not start with a hyphen.")
            risk_score += 25.0

        # --- No trailing hyphens ---
        if project_id.endswith("-"):
            issues.append("Project ID must not end with a hyphen.")
            risk_score += 25.0

        # --- Must not be all numbers ---
        if project_id and re.match(r"^[0-9]+$", project_id):
            issues.append("Project ID must not consist entirely of digits; it must contain at least one letter.")
            risk_score += 25.0

        # --- Convention warnings (optional, strict_naming) ---
        if strict_naming and project_id.lower() in _GENERIC_NAMES:
            issues.append(
                f"Project ID '{project_id}' matches a reserved/generic environment name "
                f"({', '.join(sorted(_GENERIC_NAMES))}). "
                "Use a more descriptive, unique project ID."
            )
            risk_score += 10.0

        # --- Determine is_valid (no structural violations) ---
        structural_issues_count = sum(1 for iss in issues if "generic environment name" not in iss)
        is_valid = structural_issues_count == 0

        # --- Cap risk score ---
        risk_score = min(risk_score, 100.0)

        # --- Determine status ---
        if not is_valid or risk_score > 60.0:
            status = "FAIL"
        elif risk_score >= 10.0:
            status = "WARN"
        else:
            status = "PASS"

        return GCPProjectIDOutput(
            is_valid=is_valid,
            length=length,
            issues=issues,
            risk_score=round(risk_score, 2),
            status=status,
        )
