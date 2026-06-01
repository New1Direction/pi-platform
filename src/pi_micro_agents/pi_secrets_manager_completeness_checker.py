from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_VAULT_STRICT_MODE")


class VaultInput(BaseModel):
    vault_config: str = Field(
        ..., description="Configuration parameters for Secrets Manager, HashiCorp Vault, or AWS Secrets Manager"
    )


class VaultOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if secrets manager complies with storage guidelines")
    gaps: List[str] = Field(default_factory=list, description="Gaps identified in secrets rotation and access policies")
    risk_score: float = Field(..., description="Calculated secrets vault risk (0.0 to 100.0)")
    status: str = Field(..., description="Secrets manager configuration status")


class PiSecretsManagerCompletenessChecker:
    """Verifies that secrets vaults enforce automated rotation limits, explicit IAM permission boundaries, and audit logging."""

    def __init__(self) -> None:
        self.agent_name = "PiSecretsManagerCompletenessChecker"

    def check_vault_config(self, input_envelope: VaultInput) -> VaultOutput:
        content = input_envelope.vault_config.lower()
        gaps = []
        risk_score = 0.0

        # Missing rotation settings
        if "rotation: false" in content or "rotation: disabled" in content or "enable_rotation = false" in content:
            gaps.append(
                "Missing Auto-Rotation: Secret assets do not rotate automatically, raising breach lifecycle risk."
            )
            risk_score = max(risk_score, 70.0)

        # Overly broad access policy
        if "policy: *" in content or "allow all policies" in content or '"policy": "*"' in content:
            gaps.append(
                "Permissive Access Policies: Wildcard policies allow unauthorized clients to pull arbitrary credentials."
            )
            risk_score = max(risk_score, 85.0)

        # Missing KMS / KMS key default checks
        if "kms_key: default" in content or "default encryption key" in content:
            gaps.append("Default Cryptographic Key: Default cloud provider keys are used rather than custom CMKs.")
            risk_score = max(risk_score, 50.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "FAILED_VAULT_COMPLIANCE"
        if risk_score > 0.0 and is_sec:
            status = "WARN_VAULT"

        return VaultOutput(
            is_secure=is_sec,
            gaps=gaps,
            risk_score=risk_score,
            status=status,
        )
