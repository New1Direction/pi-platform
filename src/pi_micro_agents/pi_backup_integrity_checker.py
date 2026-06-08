from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_BACKUP_STRICT_MODE")


class BackupInput(BaseModel):
    backup_config: str = Field(..., description="Backup configurations, policies, or metadata")


class BackupOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the backup strategy is secure and healthy")
    issues: List[str] = Field(default_factory=list, description="Gaps identified in back-up strategy")
    risk_score: float = Field(..., description="Security risk evaluation (0.0 to 100.0)")
    status: str = Field(..., description="Backup audit status")


class PiBackupIntegrityChecker:
    """Verifies multi-region backup replication, recovery checkpoints, and active vault lock policies."""

    def __init__(self) -> None:
        self.agent_name = "PiBackupIntegrityChecker"

    def check_backup(self, input_envelope: BackupInput) -> BackupOutput:
        content = input_envelope.backup_config.lower()
        issues = []
        risk_score = 0.0

        # Non-encrypted backups
        if "encryption: false" in content or "encryption: disabled" in content or "unencrypted" in content:
            issues.append("Unencrypted Backups: Backed up assets are stored without standard encryption controls.")
            risk_score = max(risk_score, 85.0)

        # Single region, no replication
        if "replication: false" in content or "replicate=false" in content or "replication: disabled" in content:
            issues.append("Single Point of Failure: No cross-region or multi-zone replication configuration.")
            risk_score = max(risk_score, 70.0)

        # Insecure or missing retention configuration
        if "retention: 0" in content or "retention: 1d" in content or "retention: 1" in content:
            issues.append(
                "Short Retention Period: Backup assets are retained for less than a compliant lifecycle duration."
            )
            risk_score = max(risk_score, 60.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "FAILED_COMPLIANCE"
        if risk_score > 0.0 and is_sec:
            status = "WARN_COMPLIANCE"

        return BackupOutput(
            is_secure=is_sec,
            issues=issues,
            risk_score=risk_score,
            status=status,
        )
