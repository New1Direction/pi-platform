from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_API_REVERSE_ENGINEER_AUTH_STRICT_MODE")


class ApiReverseEngineeredAuthInput(BaseModel):
    file_path: str = Field(..., description="Configuration or client source path")
    auth_code: str = Field(..., description="File content to check")
    check_level: str = Field(default="STRICT", description="Strictness level")


class ApiReverseEngineeredAuthOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if reverse-engineered auth checks passed")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable endpoints or keys")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiApiReverseEngineeredAuth:
    """Specialized endpoint micro-agent that audits application integrations for weak custom JWTs or hardcoded auth payloads."""

    def __init__(self) -> None:
        self.agent_name = "PiApiReverseEngineeredAuth"

    def audit_reverse_auth(self, input_envelope: ApiReverseEngineeredAuthInput) -> ApiReverseEngineeredAuthOutput:
        code = input_envelope.auth_code
        vulnerable_elements = []
        flagged_findings = []

        # Find weakly signed custom JWT signatures or insecure hardcoded authentication headers
        # E.g. "Authorization": "Bearer ", secret keys, "HS256" without key rotation
        weak_auth_pattern = re.search(
            r'(jwt\.sign\([\s\S]*?,\s*["\'][a-zA-Z0-9_\-]+["\']|algorithm\s*:\s*["\']none["\']|["\']?Authorization["\']?\s*:\s*["\']Bearer\s+ey[a-zA-Z0-9_\-\.]*["\'])',
            code,
        )

        if weak_auth_pattern:
            vulnerable_elements.append(weak_auth_pattern.group(1))
            flagged_findings.append(
                f"Authentication setup contains weak key signature or hardcoded token parameter: '{weak_auth_pattern.group(1)}'. "
                f"Using hardcoded authorization keys or insecure token signing methods enables reverse-engineering and session spoofing."
            )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_REVERSE_AUTH"
            else:
                status = "WARN_REVERSE_AUTH"
                is_secure = True

        return ApiReverseEngineeredAuthOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
