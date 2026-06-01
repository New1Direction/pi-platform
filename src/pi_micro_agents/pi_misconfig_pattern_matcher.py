from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_CONFIG_STRICT_MODE")


class ConfigInput(BaseModel):
    config_content: str = Field(..., description="Configuration file contents (INI, properties, or JSON)")


class MisconfigOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if configuration is free of common unsafe patterns")
    matched_patterns: List[str] = Field(
        default_factory=list, description="Common insecure patterns matched in configurations"
    )
    risk_score: float = Field(..., description="Security risk rating (0.0 to 100.0)")
    status: str = Field(..., description="Config matching validation status")


class PiMisconfigPatternMatcher:
    """Deterministic signature-based security pattern matching for standard application and infrastructure files."""

    def __init__(self) -> None:
        self.agent_name = "PiMisconfigPatternMatcher"

    def match_config(self, input_envelope: ConfigInput) -> MisconfigOutput:
        content = input_envelope.config_content.lower()
        matched = []
        risk_score = 0.0

        # Hardcoded passwords in files
        if "password=" in content or "password:" in content or "passwd=" in content or "passwd:" in content:
            if "test" in content or "admin" in content or "root" in content:
                matched.append("Hardcoded Admin Password: Plaintext credentials found in static properties file.")
                risk_score = max(risk_score, 85.0)

        # Test or sandbox systems
        if "test_mode: true" in content or "debug=true" in content or "debug: true" in content:
            matched.append("Debug Mode Enabled: Development logs active, exposing internal routing systems.")
            risk_score = max(risk_score, 60.0)

        # Insecure DB settings
        if "allow_empty_password=true" in content or "empty_password=true" in content:
            matched.append("Insecure DB Config: Database root user allowed to connect with empty password.")
            risk_score = max(risk_score, 90.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "MISCONFIG_FOUND"
        if risk_score > 0.0 and is_sec:
            status = "WARN_MISCONFIG"

        return MisconfigOutput(
            is_secure=is_sec,
            matched_patterns=matched,
            risk_score=risk_score,
            status=status,
        )
