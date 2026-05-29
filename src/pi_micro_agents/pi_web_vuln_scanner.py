from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_WEB_VULN_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_WEB_VULN_STRICT_MODE", True))
        except Exception:
            pass
    return True


class WebVulnInput(BaseModel):
    file_path: str = Field(..., description="Target web code or config file path")
    code_content: str = Field(..., description="Content of the target web application file")


class WebVulnOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the web application checks passed")
    flagged_vulnerabilities: List[str] = Field(default_factory=list, description="List of identified web vulnerabilities")
    risk_score: float = Field(..., description="Calculated risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification description")


class PiWebVulnScanner:
    """Specialized Web Application Vulnerability Scanner targeting XSS, CSRF, and security header misconfigurations."""

    def __init__(self) -> None:
        self.agent_name = "PiWebVulnScanner"

    def scan_web_vulnerabilities(self, input_envelope: WebVulnInput) -> WebVulnOutput:
        code = input_envelope.code_content
        findings = []
        risk_score = 0.0

        # Check for XSS (dangerouslySetInnerHTML, unsafe innerHTML, raw script injections)
        if "dangerouslySetInnerHTML" in code or "innerHTML =" in code:
            findings.append("Potential Cross-Site Scripting (XSS) vulnerability: unsafe raw HTML injection found.")
            risk_score = max(risk_score, 85.0)

        # Check for missing CSRF protection or disabled CSRF tokens in configs
        if "csrf: false" in code.lower() or "enable_csrf = false" in code.lower() or "csrf_protect = false" in code.lower():
            findings.append("Broken Access Control: Cross-Site Request Forgery (CSRF) protection is disabled.")
            risk_score = max(risk_score, 80.0)

        # Check for missing security headers or insecure content security policies
        if "content-security-policy" not in code.lower() and "csp" not in code.lower():
            findings.append("Missing Security Hardening: Content Security Policy (CSP) header is not defined.")
            risk_score = max(risk_score, 50.0)

        is_secure = len(findings) == 0
        status = "SECURE" if is_secure else "VULNERABLE"

        return WebVulnOutput(
            is_secure=is_secure,
            flagged_vulnerabilities=findings,
            risk_score=risk_score,
            status=status
        )
