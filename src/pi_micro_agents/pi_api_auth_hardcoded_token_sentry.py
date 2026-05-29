from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_API_AUTH_HARDCODED_TOKEN_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class ApiAuthHardcodedTokenInput(BaseModel):
    file_path: str = Field(..., description="API source file path")
    code_content: str = Field(..., description="API code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class ApiAuthHardcodedTokenOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if no hardcoded tokens/keys are present in code")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable lines or keywords")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiApiAuthHardcodedTokenSentry:
    """Specialized API Auth micro-agent that audits route files or API code for static/hardcoded credentials."""

    def __init__(self) -> None:
        self.agent_name = "PiApiAuthHardcodedTokenSentry"

    def audit_hardcoded_tokens(self, input_envelope: ApiAuthHardcodedTokenInput) -> ApiAuthHardcodedTokenOutput:
        code = input_envelope.code_content
        vulnerable_elements = []
        flagged_findings = []

        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            if clean_line.startswith("#") or clean_line.startswith("//"):
                continue

            # Look for tokens, keys, bearer credentials, passwords
            # e.g., token = "...", api_key = "...", bearer = "..."
            match = re.search(
                r'\b(token|api_key|bearer|client_secret|api_token)\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{16,})["\']',
                clean_line,
                re.IGNORECASE,
            )
            if match:
                var_name = match.group(1)
                val = match.group(2)

                # Exclude environment variable default placeholders or configs
                if not any(
                    excluded in val.lower() for excluded in ["env.", "process.env", "os.getenv", "config", "default"]
                ):
                    vulnerable_elements.append(f"Line {idx}")
                    flagged_findings.append(
                        f"Line {idx}: Static hardcoded key/token '{var_name}' detected. "
                        "Storing access tokens or secret keys directly in application source code facilitates developer-level compromises or secret leaks."
                    )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_API_AUTH_HARDCODED_TOKEN"
            else:
                status = "WARN_API_AUTH_HARDCODED_TOKEN"
                is_secure = True

        return ApiAuthHardcodedTokenOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
