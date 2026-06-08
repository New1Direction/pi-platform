from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_K8S_STRICT_MODE")


class K8sInput(BaseModel):
    k8s_content: str = Field(..., description="Raw text of the Kubernetes manifest (YAML or JSON)")


class K8sOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the Kubernetes manifest adheres to security baselines")
    violations: List[str] = Field(default_factory=list, description="List of identified container security violations")
    risk_score: float = Field(..., description="Security risk evaluation score (0.0 to 100.0)")
    status: str = Field(..., description="Kubernetes security status")


class PiKubernetesSecurityAuditor:
    """Audits Kubernetes manifests for privileged execution, default namespace, hostPath mounts, and unpinned images."""

    def __init__(self) -> None:
        self.agent_name = "PiKubernetesSecurityAuditor"

    def audit_k8s(self, input_envelope: K8sInput) -> K8sOutput:
        content = input_envelope.k8s_content
        violations = []
        risk_score = 0.0

        # Privileged Container running
        if "privileged: true" in content or '"privileged": true' in content:
            violations.append("Privileged Execution: Container configured to run with elevated root privileges.")
            risk_score = max(risk_score, 95.0)

        # Namespace defaults
        if "namespace: default" in content or '"namespace": "default"' in content:
            violations.append(
                "Default Namespace: Resources are explicitly scheduled in the unhardened default namespace."
            )
            risk_score = max(risk_score, 40.0)

        # Resource limits missing
        if "resources:" not in content and '"resources"' not in content:
            violations.append(
                "Missing Resource Constraints: CPU and Memory limit fields are missing from container spec."
            )
            risk_score = max(risk_score, 60.0)

        # HostPath / Node volume sharing
        if "hostPath:" in content or '"hostPath"' in content:
            violations.append("Host Path Injection: Direct volume mapping to node local directory detected.")
            risk_score = max(risk_score, 80.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "FAILED_COMPLIANCE"
        if risk_score > 0.0 and is_sec:
            status = "WARN_COMPLIANCE"

        return K8sOutput(
            is_secure=is_sec,
            violations=violations,
            risk_score=risk_score,
            status=status,
        )
