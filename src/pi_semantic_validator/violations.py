"""Deterministic Violation Models.

Every violation is evidence-bound, schema-validated, and fail-closed.
No inference. No speculative causality.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pi_semantic_validator.models import GovernanceViolation


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _make_violation_id() -> str:
    return f"viol_{uuid.uuid4().hex[:16]}"


def _hash_context(ctx: Dict[str, Any]) -> str:
    payload = json.dumps(ctx, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


class ViolationBuilder:
    """Deterministic builder for governance violations.

    Every violation contains:
      * exact rule
      * provenance chain
      * file/module evidence
      * semantic path
      * replay evidence if applicable
    """

    def __init__(self, pass_name: str) -> None:
        self.pass_name = pass_name

    def build(
        self,
        rule: str,
        severity: str,
        context: Dict[str, Any],
        action_taken: str = "HALT",
    ) -> GovernanceViolation:
        return GovernanceViolation(
            violation_id=_make_violation_id(),
            rule=rule,
            pass_name=self.pass_name,
            severity=severity,  # type: ignore[arg-type]
            context=context,
            action_taken=action_taken,
            detected_at=_now(),
        )

    def critical(
        self,
        rule: str,
        endpoint: str = "",
        field_path: str = "",
        provenance: List[str] | None = None,
        replay_evidence: List[str] | None = None,
        file_evidence: str = "",
        module_evidence: str = "",
        extra: Dict[str, Any] | None = None,
    ) -> GovernanceViolation:
        ctx: Dict[str, Any] = {
            "endpoint": endpoint,
            "field_path": field_path,
            "provenance_chain": provenance or [],
            "file_evidence": file_evidence,
            "module_evidence": module_evidence,
            "replay_evidence": replay_evidence or [],
        }
        if extra:
            ctx.update(extra)
        return self.build(rule=rule, severity="CRITICAL", context=ctx, action_taken="HALT")

    def error(
        self,
        rule: str,
        endpoint: str = "",
        field_path: str = "",
        provenance: List[str] | None = None,
        replay_evidence: List[str] | None = None,
        file_evidence: str = "",
        module_evidence: str = "",
        extra: Dict[str, Any] | None = None,
    ) -> GovernanceViolation:
        ctx: Dict[str, Any] = {
            "endpoint": endpoint,
            "field_path": field_path,
            "provenance_chain": provenance or [],
            "file_evidence": file_evidence,
            "module_evidence": module_evidence,
            "replay_evidence": replay_evidence or [],
        }
        if extra:
            ctx.update(extra)
        return self.build(rule=rule, severity="ERROR", context=ctx, action_taken="HALT")

    def warning(
        self,
        rule: str,
        endpoint: str = "",
        field_path: str = "",
        provenance: List[str] | None = None,
        replay_evidence: List[str] | None = None,
        file_evidence: str = "",
        module_evidence: str = "",
        extra: Dict[str, Any] | None = None,
    ) -> GovernanceViolation:
        ctx: Dict[str, Any] = {
            "endpoint": endpoint,
            "field_path": field_path,
            "provenance_chain": provenance or [],
            "file_evidence": file_evidence,
            "module_evidence": module_evidence,
            "replay_evidence": replay_evidence or [],
        }
        if extra:
            ctx.update(extra)
        return self.build(rule=rule, severity="WARNING", context=ctx, action_taken="LOG")
