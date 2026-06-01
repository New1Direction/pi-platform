"""Temporal Replay Engine.

Read-only historical state reconstruction from SnapshotRegistry.
Deterministic checkpoint system with strict no-mutation boundary.

NO runtime mutation. NO worker triggering. NO re-entry into orchestration.
All operations are analytical, visualization, or inspection only.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, List, Optional, Tuple

from pydantic import BaseModel, Field

from pi_interoperability_layer.snapshot.artifacts import SnapshotArtifact, SnapshotType
from pi_interoperability_layer.snapshot.clock import TimestampMarker, canonical_timestamp
from pi_interoperability_layer.snapshot.registry import SnapshotRegistry

# ──────────────────────────────
#  Replay Primitives
# ──────────────────────────────


class ReplayCheckpoint(BaseModel):
    """Immutable checkpoint of state at a specific timestamp.

    Produced by reconstruct_state_at(). Read-only. Cannot be used to
    trigger mutations or re-enter orchestration.
    """

    checkpoint_id: str
    tenant_id: str
    source_id: str
    snapshot_type: SnapshotType
    # The reconstructed state snapshot (may be a composite of multiple)
    reconstructed_snapshot: SnapshotArtifact
    # Evidence: which snapshots were used to build this checkpoint
    source_snapshot_ids: List[str] = Field(default_factory=list)
    # Exact timestamp the checkpoint represents
    target_timestamp: datetime
    # The actual timestamp of the nearest preceding snapshot
    nearest_snapshot_timestamp: datetime
    # Deterministic hash for integrity
    checkpoint_hash: str = ""
    # Explicit no-mutation seal
    read_only: bool = True
    model_config = {"frozen": True}

    def model_post_init(self, __context: Any) -> None:
        if not self.checkpoint_hash:
            object.__setattr__(self, "checkpoint_hash", self._compute_hash())

    def _compute_hash(self) -> str:
        payload = {
            "checkpoint_id": self.checkpoint_id,
            "tenant_id": self.tenant_id,
            "source_id": self.source_id,
            "snapshot_type": self.snapshot_type.value,
            "source_snapshot_ids": sorted(self.source_snapshot_ids),
            "target_timestamp": canonical_timestamp(self.target_timestamp),
            "nearest_snapshot_timestamp": canonical_timestamp(self.nearest_snapshot_timestamp),
            "read_only": self.read_only,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()


class ReplayTimeline(BaseModel):
    """Ordered timeline of snapshots for a specific (tenant, source, type).

    Read-only analytical view. No mutation operations.
    """

    timeline_id: str
    tenant_id: str
    source_id: str
    snapshot_type: SnapshotType
    checkpoints: List[ReplayCheckpoint] = Field(default_factory=list)
    # Time range covered
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    total_snapshots: int = 0
    model_config = {"frozen": False}

    def add_checkpoint(self, cp: ReplayCheckpoint) -> None:
        """Append a checkpoint. Maintains temporal ordering."""
        if cp.tenant_id != self.tenant_id:
            raise ValueError("Tenant mismatch in timeline")
        if cp.source_id != self.source_id:
            raise ValueError("Source mismatch in timeline")
        if cp.snapshot_type != self.snapshot_type:
            raise ValueError("Type mismatch in timeline")

        self.checkpoints.append(cp)
        self.checkpoints.sort(key=lambda c: canonical_timestamp(c.target_timestamp))
        self.total_snapshots = len(self.checkpoints)
        if self.start_time is None or cp.target_timestamp < self.start_time:
            self.start_time = cp.target_timestamp
        if self.end_time is None or cp.target_timestamp > self.end_time:
            self.end_time = cp.target_timestamp


# ──────────────────────────────
#  Replay Engine
# ──────────────────────────────


class TemporalReplayEngine:
    """Deterministic temporal replay engine.

    Provides read-only state reconstruction at any historical point.
    Strict no-mutation boundary: the engine never writes to the registry,
    never triggers workers, never mutates runtime state.

    All outputs are ReplayCheckpoint objects with read_only=True.
    """

    def __init__(self, registry: SnapshotRegistry) -> None:
        self.registry = registry

    def reconstruct_state_at(
        self,
        tenant_id: str,
        source_id: str,
        snapshot_type: SnapshotType,
        target_timestamp: datetime,
    ) -> Optional[ReplayCheckpoint]:
        """Reconstruct the state of a system at a specific historical timestamp.

        Returns the nearest snapshot at or before the target timestamp.
        If no such snapshot exists, returns None.

        The returned checkpoint is sealed read_only=True.
        """
        # List all snapshots for this triple, ordered ascending
        snapshots = self.registry.list_snapshots(
            tenant_id=tenant_id,
            source_id=source_id,
            snapshot_type=snapshot_type,
            before_marker=self._marker_from_timestamp(target_timestamp),
            limit=1000,
        )
        if not snapshots:
            return None

        # The nearest snapshot is the last one before target
        nearest = snapshots[-1]

        cp_id = f"replay_{tenant_id}_{source_id}_{snapshot_type.value}_{canonical_timestamp(target_timestamp)}"

        return ReplayCheckpoint(
            checkpoint_id=cp_id,
            tenant_id=tenant_id,
            source_id=source_id,
            snapshot_type=snapshot_type,
            reconstructed_snapshot=nearest,
            source_snapshot_ids=[nearest.snapshot_id],
            target_timestamp=target_timestamp,
            nearest_snapshot_timestamp=nearest.timestamp_marker.wall_time,
            read_only=True,
        )

    def build_timeline(
        self,
        tenant_id: str,
        source_id: str,
        snapshot_type: SnapshotType,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> ReplayTimeline:
        """Build a full replay timeline for a system over a time range.

        Read-only analytical view. Every point in the timeline is a
        read-only checkpoint.
        """
        snapshots = self.registry.list_snapshots(
            tenant_id=tenant_id,
            source_id=source_id,
            snapshot_type=snapshot_type,
            after_marker=self._marker_from_timestamp(start) if start else None,
            before_marker=self._marker_from_timestamp(end) if end else None,
            limit=10000,
        )

        timeline_id = f"timeline_{tenant_id}_{source_id}_{snapshot_type.value}"
        timeline = ReplayTimeline(
            timeline_id=timeline_id,
            tenant_id=tenant_id,
            source_id=source_id,
            snapshot_type=snapshot_type,
        )

        for snap in snapshots:
            cp = ReplayCheckpoint(
                checkpoint_id=f"{timeline_id}_{snap.snapshot_id}",
                tenant_id=tenant_id,
                source_id=source_id,
                snapshot_type=snapshot_type,
                reconstructed_snapshot=snap,
                source_snapshot_ids=[snap.snapshot_id],
                target_timestamp=snap.timestamp_marker.wall_time,
                nearest_snapshot_timestamp=snap.timestamp_marker.wall_time,
                read_only=True,
            )
            timeline.add_checkpoint(cp)

        return timeline

    def diff_at_points(
        self,
        tenant_id: str,
        source_id: str,
        snapshot_type: SnapshotType,
        timestamp_a: datetime,
        timestamp_b: datetime,
    ) -> Tuple[Optional[ReplayCheckpoint], Optional[ReplayCheckpoint]]:
        """Get read-only checkpoints at two historical points for comparison.

        Returns (checkpoint_a, checkpoint_b). Both are read-only.
        Caller may use SemanticDiffEngine to compute drift between them.
        """
        cp_a = self.reconstruct_state_at(tenant_id, source_id, snapshot_type, timestamp_a)
        cp_b = self.reconstruct_state_at(tenant_id, source_id, snapshot_type, timestamp_b)
        return (cp_a, cp_b)

    def list_available_sources(
        self,
        tenant_id: str,
    ) -> List[Tuple[str, SnapshotType, int]]:
        """List all (source_id, snapshot_type, count) for a tenant.

        Read-only inventory. Returns empty list for unknown tenant.
        """
        results: List[Tuple[str, SnapshotType, int]] = []
        seen: set = set()
        for key in self.registry._chains.keys():
            t_id, s_id, s_type = key
            if t_id != tenant_id:
                continue
            chain = self.registry._chains[key]
            if (s_id, s_type) not in seen:
                seen.add((s_id, s_type))
                results.append((s_id, s_type, len(chain.snapshot_ids)))
        return results

    def _marker_from_timestamp(self, dt: Optional[datetime]) -> Optional[TimestampMarker]:
        """Convert a datetime to a TimestampMarker for registry queries."""
        if dt is None:
            return None
        return TimestampMarker(
            wall_time=dt,
            sequence_number=0,
            clock_id="replay_query",
        )
