from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_KUBERNETES_ROOT_EXECUTION_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class KubernetesRootExecutionInput(BaseModel):
    file_path: str = Field(..., description="Kubernetes manifest file path")
    yaml_code: str = Field(..., description="Kubernetes manifest YAML content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class KubernetesRootExecutionOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if root execution checks passed")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable pods or containers")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiKubernetesRootExecutionLinter:
    """Specialized Infrastructure micro-agent that audits Kubernetes manifests to enforce runAsNonRoot: true."""

    def __init__(self) -> None:
        self.agent_name = "PiKubernetesRootExecutionLinter"

    def audit_kubernetes_root(self, input_envelope: KubernetesRootExecutionInput) -> KubernetesRootExecutionOutput:
        code = input_envelope.yaml_code
        vulnerable_elements = []
        flagged_findings = []

        # Parse YAML manifests for runAsNonRoot and runAsUser
        # Simple line-by-line / section-based checks to ensure safety
        lines = code.splitlines()
        has_security_context = False
        has_run_as_non_root = False
        
        for idx, line in enumerate(lines, 1):
            if "securityContext:" in line:
                has_security_context = True
            if "runAsNonRoot: true" in line:
                has_run_as_non_root = True
            if "runAsUser: 0" in line or "runAsUser:0" in line:
                vulnerable_elements.append(f"Line {idx}")
                flagged_findings.append(
                    f"Line {idx}: Explicit runAsUser is set to root (0). This overrides pod execution boundaries and exposes the host."
                )

        if has_security_context and not has_run_as_non_root:
            vulnerable_elements.append("securityContext")
            flagged_findings.append(
                "Manifest specifies securityContext but omits 'runAsNonRoot: true'. This allows containers to execute as root."
            )
        elif not has_security_context:
            vulnerable_elements.append("missing securityContext")
            flagged_findings.append(
                "Manifest completely omits securityContext specifications. All container pods should enforce non-root privileges."
            )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_KUBERNETES_ROOT_EXECUTION"
            else:
                status = "WARN_KUBERNETES_ROOT_EXECUTION"
                is_secure = True

        return KubernetesRootExecutionOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
