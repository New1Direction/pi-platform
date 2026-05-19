"""Artifact Bus: immutable slot-based artifact exchange.

Deterministic artifact routing between workers.
No in-place mutation. Every write creates a new slot version.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ArtifactSlot(BaseModel):
    """Immutable artifact slot with versioning and fingerprinting."""

    slot_id: str = Field(default_factory=lambda: f"slot_{uuid.uuid4().hex[:16]}")
    slot_version: int = 1
    producer_worker_id: str = ""
    artifact_type: str = ""  # e.g. "SemanticIRTrace", "DependencyGraph"
    schema_version: str = "0.0.0"
    payload: Dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = ""
    provenance_receipt_ids: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"frozen": False}

    def compute_fingerprint(self) -> str:
        payload_bytes = json.dumps(self.payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        return hashlib.sha256(payload_bytes).hexdigest()

    def freeze(self) -> "ArtifactSlot":
        fp = self.compute_fingerprint()
        return self.model_copy(update={"fingerprint": fp})


class ArtifactBus:
    """Central immutable artifact bus."""

    def __init__(self) -> None:
        self._slots: Dict[str, ArtifactSlot] = {}
        self._slot_versions: Dict[str, List[str]] = {}  # slot_family -> [slot_id_v1, slot_id_v2]

    def write(self, slot: ArtifactSlot) -> ArtifactSlot:
        frozen = slot.freeze()
        self._slots[frozen.slot_id] = frozen
        family = f"{frozen.artifact_type}:{frozen.producer_worker_id}"
        self._slot_versions.setdefault(family, []).append(frozen.slot_id)
        return frozen

    def read(self, slot_id: str) -> Optional[ArtifactSlot]:
        return self._slots.get(slot_id)

    def latest_for_family(self, artifact_type: str, producer_worker_id: str) -> Optional[ArtifactSlot]:
        family = f"{artifact_type}:{producer_worker_id}"
        versions = self._slot_versions.get(family, [])
        if not versions:
            return None
        return self._slots[versions[-1]]

    def all_versions_for_family(self, artifact_type: str, producer_worker_id: str) -> List[ArtifactSlot]:
        family = f"{artifact_type}:{producer_worker_id}"
        return [self._slots[sid] for sid in self._slot_versions.get(family, [])]

    def list_families(self) -> List[str]:
        return list(self._slot_versions.keys())
