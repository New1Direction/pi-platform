from __future__ import annotations

import json
import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_GCPCREDENTIALFILEAUDITOR_STRICT_MODE")


# Required fields per credential type
_REQUIRED_FIELDS_SERVICE_ACCOUNT = [
    "type",
    "project_id",
    "private_key_id",
    "private_key",
    "client_email",
    "client_id",
    "auth_uri",
    "token_uri",
]

_KNOWN_TYPES = {
    "service_account",
    "authorized_user",
    "external_account",
    "impersonated_service_account",
}

_VALID_PRIVATE_KEY_HEADERS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
)


class GCPCredentialFileInput(BaseModel):
    credential_json: str = Field(..., description="Raw JSON text of the GCP credential file")
    source: str = Field(
        default="service_account.json",
        description="Filename or source path of the credential file (informational)",
    )


class GCPCredentialFileOutput(BaseModel):
    is_valid: bool = Field(..., description="True if the credential file passes all required checks")
    credential_type: str = Field(..., description="Detected credential type from the 'type' field")
    project_id: str = Field(..., description="project_id value extracted from the credential file")
    client_email: str = Field(..., description="client_email value extracted from the credential file")
    issues: List[str] = Field(default_factory=list, description="List of validation issues or warnings")
    risk_score: float = Field(..., description="Risk score from 0.0 (no risk) to 100.0 (maximum risk)")
    status: str = Field(..., description="Audit result status: PASS, WARN, FAIL, or ERROR")


class PiGCPCredentialFileAuditor:
    """Audits a GCP credential JSON file for structural validity, type safety, and security posture."""

    def __init__(self) -> None:
        self.agent_name = "PiGCPCredentialFileAuditor"

    def execute(self, input_envelope: GCPCredentialFileInput) -> GCPCredentialFileOutput:
        """Parse and validate a GCP credential JSON file.

        Args:
            input_envelope: Contains raw credential JSON and optional source path.

        Returns:
            A GCPCredentialFileOutput with validation results, risk score, and status.
        """
        issues: List[str] = []
        risk_score: float = 0.0

        # --- Parse JSON ---
        try:
            cred = json.loads(input_envelope.credential_json)
        except json.JSONDecodeError as exc:
            return GCPCredentialFileOutput(
                is_valid=False,
                credential_type="unknown",
                project_id="",
                client_email="",
                issues=[f"JSON parse error: {exc}"],
                risk_score=50.0,
                status="ERROR",
            )

        if not isinstance(cred, dict):
            return GCPCredentialFileOutput(
                is_valid=False,
                credential_type="unknown",
                project_id="",
                client_email="",
                issues=["Credential JSON must be a JSON object (dict), not a list or scalar."],
                risk_score=50.0,
                status="ERROR",
            )

        # --- Detect credential type ---
        credential_type: str = cred.get("type", "")
        if not credential_type:
            issues.append("Missing required field: 'type'")
            risk_score += 20.0
        elif credential_type not in _KNOWN_TYPES:
            issues.append(
                f"Unrecognized credential type '{credential_type}'. Expected one of: {', '.join(sorted(_KNOWN_TYPES))}."
            )
            risk_score += 20.0

        # --- User credentials warning ---
        if credential_type == "authorized_user":
            issues.append(
                "WARNING: Credential type is 'authorized_user' (personal OAuth token). "
                "Service account credentials are strongly preferred for production workloads."
            )
            risk_score += 30.0

        # --- Required field validation (service_account) ---
        if credential_type == "service_account":
            for field in _REQUIRED_FIELDS_SERVICE_ACCOUNT:
                if field not in cred or cred[field] in (None, ""):
                    issues.append(f"Missing or empty required field: '{field}'")
                    risk_score += 20.0

        # --- Extract informational fields ---
        project_id: str = cred.get("project_id", "")
        client_email: str = cred.get("client_email", "")

        # --- client_email format validation ---
        if client_email:
            # Pattern: localpart@project.iam.gserviceaccount.com
            sa_email_pattern = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9\-]+\.iam\.gserviceaccount\.com$")
            if not sa_email_pattern.match(client_email):
                issues.append(
                    f"client_email '{client_email}' does not match expected service account "
                    "format: <name>@<project>.iam.gserviceaccount.com"
                )
                risk_score += 15.0
        elif credential_type == "service_account":
            # Already flagged as missing above; skip double-count
            pass

        # --- private_key_id length check ---
        private_key_id: str = cred.get("private_key_id", "")
        if private_key_id and len(private_key_id) < 10:
            issues.append(
                f"private_key_id is suspiciously short ({len(private_key_id)} chars). "
                "Expected at least 10 characters for a valid key ID."
            )

        # --- private_key header check ---
        private_key: str = cred.get("private_key", "")
        if private_key:
            stripped = private_key.strip()
            if not any(stripped.startswith(header) for header in _VALID_PRIVATE_KEY_HEADERS):
                issues.append(
                    "private_key does not start with a recognized PEM header "
                    "('-----BEGIN RSA PRIVATE KEY-----' or '-----BEGIN PRIVATE KEY-----')."
                )
                risk_score += 10.0

        # --- universe_domain check ---
        universe_domain: str = cred.get("universe_domain", "googleapis.com")
        if universe_domain and universe_domain != "googleapis.com":
            issues.append(
                f"Non-standard universe_domain '{universe_domain}'. "
                "Expected 'googleapis.com' for standard GCP environments."
            )

        # --- Determine is_valid ---
        # Valid if no FAIL-level issues (missing required fields / user creds)
        structural_issues = [i for i in issues if "Missing or empty required field" in i]
        is_valid = (
            credential_type in _KNOWN_TYPES
            and credential_type != "authorized_user"
            and len(structural_issues) == 0
            and bool(client_email)
        )

        # --- Cap risk score ---
        risk_score = min(risk_score, 100.0)

        # --- Determine status ---
        if risk_score > 60.0 or not is_valid:
            status = "FAIL"
        elif risk_score >= 30.0:
            status = "WARN"
        else:
            status = "PASS"

        return GCPCredentialFileOutput(
            is_valid=is_valid,
            credential_type=credential_type,
            project_id=project_id,
            client_email=client_email,
            issues=issues,
            risk_score=round(risk_score, 2),
            status=status,
        )
