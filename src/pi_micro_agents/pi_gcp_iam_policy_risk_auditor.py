from __future__ import annotations

import json
import re
from typing import List

from pydantic import BaseModel, Field


class GCPIAMPolicyInput(BaseModel):
    policy_json: str = Field(..., description="Raw JSON content of the GCP IAM Policy to audit")
    risk_tolerance: str = Field(default="medium", description="Risk tolerance level: low, medium, or high")


class GCPIAMPolicyOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no high-risk IAM bindings are detected")
    findings: List[str] = Field(default_factory=list, description="Detailed security risk findings")
    risk_score: float = Field(..., description="Calculated IAM policy risk score from 0.0 to 100.0")
    status: str = Field(..., description="Auditing status: PASS, WARN, or FAIL")


class PiGCPIAMPolicyRiskAuditor:
    """Audits GCP IAM policies (bindings, roles, members) to detect overly permissive roles, public exposures, and compliance risks."""

    def __init__(self) -> None:
        self.agent_name = "PiGCPIAMPolicyRiskAuditor"

    def execute(self, input_envelope: GCPIAMPolicyInput) -> GCPIAMPolicyOutput:
        policy_json = input_envelope.policy_json
        risk_tolerance = input_envelope.risk_tolerance.lower()

        findings = []
        risk_score = 0.0

        try:
            policy = json.loads(policy_json)
        except json.JSONDecodeError as e:
            findings.append(f"Failed to parse IAM Policy JSON: {str(e)}")
            return GCPIAMPolicyOutput(
                is_secure=False,
                findings=findings,
                risk_score=50.0,
                status="FAIL",
            )

        bindings = policy.get("bindings", [])
        if not isinstance(bindings, list):
            findings.append("IAM Policy must contain a 'bindings' list.")
            return GCPIAMPolicyOutput(
                is_secure=False,
                findings=findings,
                risk_score=40.0,
                status="FAIL",
            )

        privileged_roles = ["roles/owner", "roles/editor"]

        for idx, binding in enumerate(bindings):
            if not isinstance(binding, dict):
                findings.append(f"Binding at index {idx} is not a dictionary.")
                risk_score += 10.0
                continue

            role = binding.get("role", "")
            members = binding.get("members", [])

            if not role:
                findings.append(f"Binding at index {idx} is missing 'role'.")
                risk_score += 15.0
                continue

            # Rule 1: Check privileged roles
            is_role_privileged = False
            if role in privileged_roles:
                findings.append(f"Highly privileged role '{role}' binding detected.")
                risk_score += 30.0
                is_role_privileged = True
            elif "admin" in role.lower():
                findings.append(f"Administrative role '{role}' binding detected.")
                risk_score += 20.0
                is_role_privileged = True

            # Rule 2: Check wildcards in custom roles
            if role == "*":
                findings.append("Wildcard '*' role binding detected, granting absolute access.")
                risk_score += 50.0

            for member in members:
                # Rule 3: Check public exposure
                if member in ["allUsers", "allAuthenticatedUsers"]:
                    if is_role_privileged:
                        findings.append(f"CRITICAL: Public member '{member}' granted privileged role '{role}'.")
                        risk_score += 50.0
                    else:
                        findings.append(f"Public member '{member}' granted role '{role}'.")
                        risk_score += 30.0

                # Rule 4: Validate service account format if member starts with serviceAccount:
                if member.startswith("serviceAccount:"):
                    sa_email = member.split("serviceAccount:")[-1]
                    if not re.match(r"^[a-zA-Z0-9-._]+@[a-zA-Z0-9-._]+\.iam\.gserviceaccount\.com$", sa_email):
                        findings.append(
                            f"Service account member '{sa_email}' has non-standard email domain formatting."
                        )
                        risk_score += 15.0

        # Adjust risk score based on tolerance
        if risk_tolerance == "low":
            risk_score *= 1.25
        elif risk_tolerance == "high":
            risk_score *= 0.75

        risk_score = min(risk_score, 100.0)

        # Secure definition
        fail_threshold = 30.0 if risk_tolerance == "low" else 60.0
        is_secure = risk_score < fail_threshold

        if risk_score > fail_threshold:
            status = "FAIL"
        elif risk_score >= 20.0:
            status = "WARN"
        else:
            status = "PASS"

        return GCPIAMPolicyOutput(
            is_secure=is_secure,
            findings=findings,
            risk_score=risk_score,
            status=status,
        )
