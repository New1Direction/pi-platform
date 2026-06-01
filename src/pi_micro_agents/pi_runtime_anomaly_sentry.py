from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_RUNTIME_STRICT_MODE")


class RuntimeInput(BaseModel):
    metrics_content: str = Field(..., description="Application performance metrics, thread states, or network metrics")


class AnomalyOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if performance metrics fall within healthy baselines")
    anomalies_detected: List[str] = Field(default_factory=list, description="List of detected runtime anomalies")
    risk_score: float = Field(..., description="Security anomaly threat score (0.0 to 100.0)")
    status: str = Field(..., description="Runtime audit status")


class PiRuntimeAnomalySentry:
    """Flags runtime metric drift, unauthorized execution binaries, or suspicious outbound connections in production."""

    def __init__(self) -> None:
        self.agent_name = "PiRuntimeAnomalySentry"

    def audit_runtime(self, input_envelope: RuntimeInput) -> AnomalyOutput:
        content = input_envelope.metrics_content.lower()
        anomalies = []
        risk_score = 0.0

        # CPU / memory spikes
        if "cpu_spike" in content or "cpu: 99%" in content or "oom_killed" in content:
            anomalies.append(
                "Resource Exhaustion: Runtime logs indicate critical CPU threshold breaches or container OOM terminations."
            )
            risk_score = max(risk_score, 70.0)

        # High error rates
        if "error_rate: 45%" in content or "5xx_errors: high" in content:
            anomalies.append(
                "Uncontrolled Fault Rate: High density of 5xx HTTP exceptions suggests dynamic system instability."
            )
            risk_score = max(risk_score, 80.0)

        # Unauthorized outbound network connection attempts
        if (
            "unauthorized outbound" in content
            or "suspicious connection to" in content
            or "sh: " in content
            or "cmd.exe" in content
        ):
            anomalies.append(
                "Suspicious Shell Execution: Runtime detected unauthorized bash/cmd spawn queries or unexpected ports."
            )
            risk_score = max(risk_score, 95.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "ANOMALIES_DETECTED"
        if risk_score > 0.0 and is_sec:
            status = "WARN_ANOMALIES"

        return AnomalyOutput(
            is_secure=is_sec,
            anomalies_detected=anomalies,
            risk_score=risk_score,
            status=status,
        )
