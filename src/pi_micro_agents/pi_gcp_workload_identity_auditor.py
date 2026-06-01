from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class WorkloadIdentityInput(BaseModel):
    uses_service_account_key_file: bool = Field(
        ...,
        description="Whether the workload utilizes a physical service account key file (.json) for credentials",
    )
    has_workload_identity_binding: bool = Field(
        ...,
        description="Whether the workload has a configured Workload Identity binding to a GCP service account",
    )
    service_account_email: str = Field(
        ...,
        description="Email address of the associated service account",
    )
    deployment_target: str = Field(
        default="gke",
        description="Deployment environment target: gke, cloud_run, functions, or compute_engine",
    )


class WorkloadIdentityOutput(BaseModel):
    is_compliant: bool = Field(..., description="True if the security posture meets Workload Identity standards")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    recommendation: str = Field(..., description="Clear recommended steps to improve compliance")
    issues: List[str] = Field(default_factory=list, description="List of identified Workload Identity risks")
    status: str = Field(..., description="Audit status: PASS, WARN, or FAIL")


class PiGCPWorkloadIdentityAuditor:
    """Audits deployment configurations to verify Workload Identity compliance standards and flags insecure static service account keys."""

    def __init__(self) -> None:
        self.agent_name = "PiGCPWorkloadIdentityAuditor"

    def execute(self, input_envelope: WorkloadIdentityInput) -> WorkloadIdentityOutput:
        """Analyze workload configuration parameters for Workload Identity compliance."""
        uses_key_file = input_envelope.uses_service_account_key_file
        has_binding = input_envelope.has_workload_identity_binding
        sa_email = input_envelope.service_account_email
        target = input_envelope.deployment_target

        issues: List[str] = []
        recommendations: List[str] = []
        risk_score = 0.0

        # 1. Physical key file check
        if uses_key_file:
            issues.append(
                "VULNERABILITY: Workload is using a static service account private key file. "
                "Static key files present high credential exposure risks."
            )
            risk_score += 40.0
            recommendations.append(
                "Disable static service account key files. Transition to IAM Workload Identity "
                "or dynamic instance metadata credentials."
            )

        # 2. Workload Identity binding check
        if target.lower() == "gke" and not has_binding:
            issues.append(
                "WARNING: Workload on GKE is active without a Workload Identity binding. "
                "It may fall back to GCE node default service account credentials."
            )
            risk_score += 30.0
            recommendations.append(
                "Enable Workload Identity on GKE. Bind the Kubernetes Service Account (KSA) "
                "to a dedicated GCP Service Account (GSA) using IAM binding rules."
            )

        # 3. Default service account checks
        is_default_sa = False
        if sa_email:
            sa_email_lower = sa_email.lower()
            if (
                sa_email_lower.endswith("-compute@developer.gserviceaccount.com")
                or sa_email_lower.endswith("@appspot.gserviceaccount.com")
                or sa_email_lower.startswith("default-")
            ):
                is_default_sa = True

        if is_default_sa:
            issues.append(
                f"WARNING: Workload is configured to use a GCP default service account ('{sa_email}'). "
                "Default service accounts contain excessive permissions."
            )
            risk_score += 25.0
            recommendations.append(
                "Create a dedicated, fine-grained service account following the Principle of Least Privilege, "
                "and bind it to the workload instead of the default."
            )

        # 4. Check email format
        if sa_email:
            if "@" not in sa_email or "." not in sa_email:
                issues.append(f"Invalid service account email format: '{sa_email}'.")
                risk_score += 15.0

        risk_score = min(risk_score, 100.0)
        is_compliant = risk_score < 50.0

        if risk_score >= 60.0:
            status = "FAIL"
        elif risk_score >= 30.0:
            status = "WARN"
        else:
            status = "PASS"

        recommendation_str = (
            " ".join(recommendations) if recommendations else "Security posture is excellent. No changes required."
        )

        return WorkloadIdentityOutput(
            is_compliant=is_compliant,
            risk_score=risk_score,
            recommendation=recommendation_str,
            issues=issues,
            status=status,
        )
