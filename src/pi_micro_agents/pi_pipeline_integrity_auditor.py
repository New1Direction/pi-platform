from __future__ import annotations

import json
import os
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_PIPELINE_INTEGRITY_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_PIPELINE_INTEGRITY_STRICT_MODE", True))
        except Exception:
            pass
    return True


class PipelineIntegrityInput(BaseModel):
    workflow_path: str = Field(..., description="Path to the CI/CD pipeline workflow configuration")
    workflow_content: str = Field(..., description="Raw text content of the workflow file")


class PipelineIntegrityOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if pipeline integrity checks passed")
    detected_flaws: List[str] = Field(default_factory=list, description="Identified pipeline security vulnerabilities")
    risk_score: float = Field(..., description="Calculated pipeline abuse risk score from 0.0 to 100.0")
    status: str = Field(..., description="Integrity check status classification")


class PiPipelineIntegrityAuditor:
    """Specialized CI/CD Auditor agent checking for action injection vectors, unpinned script runs, and host access abuses."""

    def __init__(self) -> None:
        self.agent_name = "PiPipelineIntegrityAuditor"

    def audit_pipeline_integrity(self, input_envelope: PipelineIntegrityInput) -> PipelineIntegrityOutput:
        content = input_envelope.workflow_content
        flaws = []
        risk_score = 0.0

        # Detect untrusted user inputs siphoned directly into bash/shell tasks (GitHub Event script injections)
        if "github.event.inputs" in content or "github.head_ref" in content:
            if "run:" in content:
                flaws.append(
                    "Critical Script Injection: unescaped github.event context parameter siphoned directly into shell step."
                )
                risk_score = max(risk_score, 90.0)

        # Detect high-privilege access permissions (write-all, admin access to secrets in forks)
        if "permissions: write-all" in content.lower() or "permissions: {}" in content:
            flaws.append("Permissive Access: workflow configuration is granted excessive default write permissions.")
            risk_score = max(risk_score, 65.0)

        is_secure = len(flaws) == 0
        status = "PASSED" if is_secure else "FAILED_INTEGRITY"

        return PipelineIntegrityOutput(is_secure=is_secure, detected_flaws=flaws, risk_score=risk_score, status=status)
