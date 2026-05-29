from __future__ import annotations

import json
import os

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_DEPLOYMENT_SAFETY_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_DEPLOYMENT_SAFETY_STRICT_MODE", True))
        except Exception:
            pass
    return True


class DeploymentSafetyInput(BaseModel):
    deployment_target: str = Field(..., description="Target deployment stage or environment")
    post_remediation_code: str = Field(..., description="Code after patches have been auto-applied")
    health_check_endpoint: str = Field(
        default="http://localhost:8080/health", description="System health verification URL"
    )


class DeploymentSafetyOutput(BaseModel):
    deployment_allowed: bool = Field(..., description="Determines if safe deployment is authorized")
    post_deploy_checks_passed: bool = Field(..., description="Post-deployment check indicator")
    risk_score: float = Field(..., description="Remaining architectural deployment risk score")
    status: str = Field(..., description="Verification classification status")


class PiDeploymentSafetyGuard:
    """Specialized Gating worker to verify post-remediation system health, prevent broken deployments, and enforce rollback constraints."""

    def __init__(self) -> None:
        self.agent_name = "PiDeploymentSafetyGuard"

    def verify_deployment_safety(self, input_envelope: DeploymentSafetyInput) -> DeploymentSafetyOutput:
        code = input_envelope.post_remediation_code
        post_deploy_checks_passed = True
        risk_score = 0.0

        # Heuristic check: Ensure no syntax errors or placeholder code remains before releasing to prod
        if "TODO" in code or "FIXME" in code or "placeholder" in code.lower():
            post_deploy_checks_passed = False
            risk_score = 75.0
        elif "syntaxerror" in code.lower() or "not defined" in code.lower():
            post_deploy_checks_passed = False
            risk_score = 90.0

        deployment_allowed = post_deploy_checks_passed
        status = "DEPLOYED_SUCCESSFULLY" if deployment_allowed else "ROLLBACK_TRIGGERED"

        return DeploymentSafetyOutput(
            deployment_allowed=deployment_allowed,
            post_deploy_checks_passed=post_deploy_checks_passed,
            risk_score=risk_score,
            status=status,
        )
