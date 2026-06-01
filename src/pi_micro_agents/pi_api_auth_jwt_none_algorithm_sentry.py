from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_API_AUTH_JWT_NONE_STRICT_MODE")


class ApiAuthJWTNoneAlgorithmInput(BaseModel):
    file_path: str = Field(..., description="API code file path")
    code_content: str = Field(..., description="API code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class ApiAuthJWTNoneAlgorithmOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if JWT decoding forbids 'none' algorithm")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable lines or methods")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiApiAuthJWTNoneAlgorithmSentry:
    """Specialized API Auth micro-agent that audits JWT decoders for the insecure 'none' algorithm."""

    def __init__(self) -> None:
        self.agent_name = "PiApiAuthJWTNoneAlgorithmSentry"

    def audit_jwt_none_algorithm(self, input_envelope: ApiAuthJWTNoneAlgorithmInput) -> ApiAuthJWTNoneAlgorithmOutput:
        code = input_envelope.code_content
        vulnerable_elements = []
        flagged_findings = []

        # Find JWT decoding methods, e.g. jwt.decode or jwt.verify
        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            if "jwt.decode" in clean_line or "jwt.verify" in clean_line:
                # Check if 'none' is explicitly allowed, or algorithm verification is bypassed
                # e.g., if there's no algorithms list, or algorithms has "none"
                if (
                    "algorithms" not in clean_line
                    or "none" in clean_line.lower()
                    or "verify=False" in clean_line
                    or "verify=false" in clean_line
                ):
                    vulnerable_elements.append(f"Line {idx}")
                    flagged_findings.append(
                        f"Line {idx}: Potential insecure JWT decoding configuration: '{clean_line}'. "
                        "Allowing the 'none' signature algorithm or bypassing signature verification allows attackers to spoof token signatures."
                    )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_API_AUTH_JWT_NONE"
            else:
                status = "WARN_API_AUTH_JWT_NONE"
                is_secure = True

        return ApiAuthJWTNoneAlgorithmOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
