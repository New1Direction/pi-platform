from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_TERRAFORM_STATE_CREDENTIAL_STRICT_MODE")


class TerraformStateCredentialInput(BaseModel):
    file_path: str = Field(..., description="Terraform source file path")
    tf_code: str = Field(..., description="Terraform source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class TerraformStateCredentialOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if no hardcoded credentials exist in IaC scripts")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable lines or variables")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiTerraformStateCredentialSentry:
    """Specialized Infrastructure micro-agent that audits Terraform files for hardcoded provider secrets or keys."""

    def __init__(self) -> None:
        self.agent_name = "PiTerraformStateCredentialSentry"

    def audit_terraform_credentials(
        self, input_envelope: TerraformStateCredentialInput
    ) -> TerraformStateCredentialOutput:
        code = input_envelope.tf_code
        vulnerable_elements = []
        flagged_findings = []

        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            if clean_line.startswith("#") or clean_line.startswith("//"):
                continue

            # Check for patterns of direct credential declarations in tf files
            # e.g., secret_key = "...", access_key = "...", password = "...", token = "..."
            match = re.search(
                r'\b(secret_key|access_key|password|token|api_key|client_secret)\s*=\s*["\']([^"\']+)["\']',
                clean_line,
                re.IGNORECASE,
            )
            if match:
                var_name = match.group(1)
                val = match.group(2)

                # If value is not a standard variable reference (like var.xxx or local.xxx)
                if not val.startswith("var.") and not val.startswith("local.") and len(val) > 4:
                    vulnerable_elements.append(f"Line {idx}")
                    flagged_findings.append(
                        f"Line {idx}: Hardcoded credential value assigned to '{var_name}'."
                        "Statically declaring secrets in IaC configurations exposes credentials to all code repository readers."
                    )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_TERRAFORM_STATE_CREDENTIAL"
            else:
                status = "WARN_TERRAFORM_STATE_CREDENTIAL"
                is_secure = True

        return TerraformStateCredentialOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
