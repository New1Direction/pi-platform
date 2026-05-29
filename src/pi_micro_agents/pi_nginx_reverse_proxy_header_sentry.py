from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_NGINX_REVERSE_PROXY_STRICT_MODE")


class NginxReverseProxyHeaderInput(BaseModel):
    file_path: str = Field(..., description="Nginx config file path")
    nginx_code: str = Field(..., description="Nginx configuration code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class NginxReverseProxyHeaderOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if reverse proxy headers are secure")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable lines or blocks")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiNginxReverseProxyHeaderSentry:
    """Specialized Infrastructure micro-agent that audits Nginx configs for correct proxy header routing and options."""

    def __init__(self) -> None:
        self.agent_name = "PiNginxReverseProxyHeaderSentry"

    def audit_nginx_headers(self, input_envelope: NginxReverseProxyHeaderInput) -> NginxReverseProxyHeaderOutput:
        code = input_envelope.nginx_code
        vulnerable_elements = []
        flagged_findings = []

        # Find location blocks
        location_blocks = re.findall(r"location\s+([a-zA-Z0-9_\-\./]+)\s*\{([\s\S]*?)\}", code)

        for path, body in location_blocks:
            if "proxy_pass" in body:
                # If there's proxy_pass, check if standard headers are set to prevent spoofing
                # e.g., check for X-Forwarded-For or X-Real-IP
                has_forwarded_for = "X-Forwarded-For" in body or "proxy_set_header" in body
                if not has_forwarded_for:
                    vulnerable_elements.append(path)
                    flagged_findings.append(
                        f"Location block '{path}' executes proxy_pass but fails to configure 'X-Forwarded-For' or standard tracking headers. "
                        "This can mask client source IPs and lead to access control bypasses or spoofing vulnerabilities."
                    )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 65.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_NGINX_REVERSE_PROXY"
            else:
                status = "WARN_NGINX_REVERSE_PROXY"
                is_secure = True

        return NginxReverseProxyHeaderOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
