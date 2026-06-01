from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_RETENTION_STRICT_MODE")


class RetentionInput(BaseModel):
    policy_content: str = Field(..., description="Data retention configs, lifecycle rules, or policy files")


class RetentionOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the retention policy meets compliance data-aging rules")
    issues: List[str] = Field(
        default_factory=list, description="List of retention compliance issues or gaps identified"
    )
    risk_score: float = Field(..., description="Security risk rating (0.0 to 100.0)")
    status: str = Field(..., description="Retention compliance status")


class PiDataRetentionPolicyEnforcer:
    """Verifies automated data deletion schedules, purging PII records, and enforcing minimal storage lifetimes."""

    def __init__(self) -> None:
        self.agent_name = "PiDataRetentionPolicyEnforcer"

    def enforce_retention(self, input_envelope: RetentionInput) -> RetentionOutput:
        content = input_envelope.policy_content.lower()
        issues = []
        risk_score = 0.0

        # Retaining data indefinitely
        if "retain: indefinite" in content or "delete: never" in content or "retention: unlimited" in content:
            issues.append(
                "Indefinite Data Retention: Configuration stores user records indefinitely without automated purge triggers."
            )
            risk_score = max(risk_score, 80.0)

        # Retention of PII without strict consent controls
        if "pii: retain" in content or "personal_data: save" in content:
            if "consent_check: false" in content or "consent: false" in content:
                issues.append(
                    "Uncontrolled PII Retention: Sensitive personal identifiers stored without mandatory consent checks."
                )
                risk_score = max(risk_score, 90.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "FAILED_COMPLIANCE"
        if risk_score > 0.0 and is_sec:
            status = "WARN_COMPLIANCE"

        return RetentionOutput(
            is_secure=is_sec,
            issues=issues,
            risk_score=risk_score,
            status=status,
        )
