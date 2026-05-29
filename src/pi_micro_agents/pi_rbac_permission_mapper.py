from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_RBAC_STRICT_MODE")


class RBACInput(BaseModel):
    policy_file_path: str = Field(..., description="Path to the IAM or RBAC policy document")
    policy_content: str = Field(..., description="Raw JSON or YAML policy definition")


class RBACOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the RBAC policy enforces least privilege")
    excessive_permissions: List[str] = Field(
        default_factory=list, description="List of overly permissive or unsafe actions/roles"
    )
    risk_score: float = Field(..., description="Risk assessment score (0.0 to 100.0)")
    status: str = Field(..., description="RBAC mapping compliance status")


class PiRBACPermissionMapper:
    """Maps IAM/RBAC policies to detect least-privilege violations and wildcard actions."""

    def __init__(self) -> None:
        self.agent_name = "PiRBACPermissionMapper"

    def map_rbac_permissions(self, input_envelope: RBACInput) -> RBACOutput:
        content = input_envelope.policy_content
        excessive = []
        risk_score = 0.0

        # Action: * checks
        if (
            '"Action": "*"' in content
            or '"action": "*"' in content
            or "Action: '*'" in content
            or "action: '*'" in content
        ):
            excessive.append(
                "Wildcard Action: Policy allows arbitrary actions ('*') which violates least-privilege principles."
            )
            risk_score = max(risk_score, 95.0)

        # Resource: * checks
        if (
            '"Resource": "*"' in content
            or '"resource": "*"' in content
            or "Resource: '*'" in content
            or "resource: '*'" in content
        ):
            if "Effect: Allow" in content or '"Effect": "Allow"' in content or '"effect": "allow"' in content:
                excessive.append(
                    "Wildcard Resource: Policy allows actions on all target resources which may cause data leakage."
                )
                risk_score = max(risk_score, 70.0)

        # Privilege escalation checks: iam:PassRole or AttachRolePolicy
        if "iam:PassRole" in content or "iam:AttachRolePolicy" in content or "iam:PutUserPolicy" in content:
            excessive.append(
                "Privilege Escalation Risk: Permission grants critical IAM management controls (e.g. iam:PassRole)."
            )
            risk_score = max(risk_score, 90.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "OVERLY_PERMISSIVE"
        if risk_score > 0.0 and is_sec:
            status = "WARN_PERMISSIVE"

        return RBACOutput(
            is_secure=is_sec,
            excessive_permissions=excessive,
            risk_score=risk_score,
            status=status,
        )
