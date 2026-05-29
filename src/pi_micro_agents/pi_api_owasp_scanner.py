from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_API_STRICT_MODE")


class APIInput(BaseModel):
    api_path: str = Field(..., description="Path to the OpenAPI/Swagger API schema")
    schema_content: str = Field(..., description="Raw text content of the API schema (JSON or YAML)")


class APIOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the API schema is free of critical OWASP violations")
    owasp_violations: List[str] = Field(
        default_factory=list, description="List of OWASP API Top 10 vulnerabilities flagged"
    )
    risk_score: float = Field(..., description="Risk assessment score (0.0 to 100.0)")
    status: str = Field(..., description="API security validation status")


class PiAPIOWASPScanner:
    """Scans OpenAPI specifications for broken authentication, query injections, and missing authorization limits."""

    def __init__(self) -> None:
        self.agent_name = "PiAPIOWASPScanner"

    def scan_api(self, input_envelope: APIInput) -> APIOutput:
        content = input_envelope.schema_content.lower()
        violations = []
        risk_score = 0.0

        # API1:2023 Broken Object Level Authorization (BOLA) or Broken Authentication
        if "security:" not in content and '"security"' not in content:
            violations.append("OWASP API2 - Broken Authentication: API endpoints missing security/auth schemes.")
            risk_score = max(risk_score, 85.0)

        # API3:2023 Broken Object Property Level Authorization (BOPLA) or SQL injection points in paths
        if "{id}" in content or "{user_id}" in content:
            if "pattern:" not in content and '"pattern"' not in content:
                violations.append(
                    "OWASP API3 - Insecure Path Parameters: User-supplied identifiers lack regex input sanitization validation."
                )
                risk_score = max(risk_score, 60.0)

        # API4:2023 Unrestricted Resource Consumption
        if "limit" not in content and "page" not in content and "size" not in content:
            violations.append(
                "OWASP API4 - Unrestricted Resource Consumption: Pagination or rate-limit configurations missing on collection endpoints."
            )
            risk_score = max(risk_score, 70.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "FAILED_API_COMPLIANCE"
        if risk_score > 0.0 and is_sec:
            status = "WARN_API_COMPLIANCE"

        return APIOutput(
            is_secure=is_sec,
            owasp_violations=violations,
            risk_score=risk_score,
            status=status,
        )
