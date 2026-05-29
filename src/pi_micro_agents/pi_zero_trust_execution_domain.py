from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ZERO_TRUST_EXEC_DOMAIN_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_ZERO_TRUST_EXEC_DOMAIN_STRICT_MODE", True))
        except Exception:
            pass
    return True


class ZeroTrustExecDomainInput(BaseModel):
    file_path: str = Field(..., description="Configuration or runner file path")
    domain_code: str = Field(..., description="Content of configuration or script")
    check_level: str = Field(default="STRICT", description="Strictness level")


class ZeroTrustExecDomainOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if execution domain checks passed")
    vulnerable_elements: List[str] = Field(
        default_factory=list, description="Vulnerable configuration lines or variables"
    )
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiZeroTrustExecutionDomain:
    """Specialized environment micro-agent that audits execution shell profiles or tmux configs for permission escalations or lack of sandbox boundary restrictions."""

    def __init__(self) -> None:
        self.agent_name = "PiZeroTrustExecutionDomain"

    def audit_exec_domain(self, input_envelope: ZeroTrustExecDomainInput) -> ZeroTrustExecDomainOutput:
        code = input_envelope.domain_code
        vulnerable_elements = []
        flagged_findings = []

        # Scans for tmux socket leaks or unconstrained execution environment exports
        # E.g. tmux -S /var/run, export sandbox bypass, ssh execution, unconfined profiles
        unconstrained_tmux = re.search(
            r'(tmux\s+-S\s+/[a-zA-Z0-9_/]+|tmux\s+run-shell\s+-[b]*\s*"*[a-zA-Z0-9_\-\s]+"*|chmod\s+777|permit-root)',
            code,
        )

        if unconstrained_tmux:
            vulnerable_elements.append(unconstrained_tmux.group(1))
            flagged_findings.append(
                f"Execution domain configuration exposes unsafe shell/socket mappings: '{unconstrained_tmux.group(1)}'. "
                f"This bypasses normal role-based namespace bounds and opens vectors for host privilege escalation."
            )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ZERO_TRUST_DOMAIN"
            else:
                status = "WARN_ZERO_TRUST_DOMAIN"
                is_secure = True

        return ZeroTrustExecDomainOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
