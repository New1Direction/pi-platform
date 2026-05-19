"""Cross-Version Replay Engine.

Replay historical artifacts across runtime versions with migration-aware
reconstruction. Deterministic hydration of past events into current schemas.

No probabilistic hydration. No automatic schema adaptation. All cross-version
replay goes through explicit MigrationDAG paths registered in SchemaRegistry.

Key concepts:
- VersionedReplayContext: captures runtime version + schema version + epoch
- ReplayHydrator: applies migration chain to historical data
- RuntimeCompatibilityFence: prevents replay across incompatible versions
- CrossVersionReplayReport: deterministic summary of replay operation
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from pi_event_fabric.bus.core import (
    DomainEvent,
    EventBusStorage,
    EventReplayEngine,
    EventType,
)
from pi_event_fabric.schema.evolution import (
    ArtifactSchema,
    CompatibilityLevel,
    CompatibilityValidator,
    MigrationStep,
    SchemaRegistry,
)


# ──────────────────────────────
#  Versioned Replay Context
# ──────────────────────────────

@dataclass(frozen=True)
class VersionedReplayContext:
    """Immutable context for cross-version replay.

    Captures the exact runtime, schema, and epoch conditions under which
    replay is occurring. All replay is deterministic given this context.
    """

    source_runtime_version: str
    target_runtime_version: str
    source_schema_fingerprint: str
    target_schema_fingerprint: str
    epoch_number: int
    replay_correlation_id: str
    read_only: bool = True
    migration_path: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_runtime_version": self.source_runtime_version,
            "target_runtime_version": self.target_runtime_version,
            "source_schema_fingerprint": self.source_schema_fingerprint,
            "target_schema_fingerprint": self.target_schema_fingerprint,
            "epoch_number": self.epoch_number,
            "replay_correlation_id": self.replay_correlation_id,
            "read_only": self.read_only,
            "migration_path": list(self.migration_path),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "VersionedReplayContext":
        return cls(
            source_runtime_version=d["source_runtime_version"],
            target_runtime_version=d["target_runtime_version"],
            source_schema_fingerprint=d["source_schema_fingerprint"],
            target_schema_fingerprint=d["target_schema_fingerprint"],
            epoch_number=d["epoch_number"],
            replay_correlation_id=d["replay_correlation_id"],
            read_only=d.get("read_only", True),
            migration_path=tuple(d.get("migration_path", [])),
        )


# ──────────────────────────────
#  Runtime Compatibility Fence
# ──────────────────────────────

class RuntimeCompatibilityFence:
    """Deterministic boundary for cross-version replay.

    Prevents replay across incompatible runtime versions.
    All version transitions must be explicitly approved.
    """

    APPROVED_TRANSITIONS: Dict[Tuple[str, str], bool] = {}  # (from, to) -> approved

    @classmethod
    def approve_transition(cls, from_version: str, to_version: str) -> None:
        cls.APPROVED_TRANSITIONS[(from_version, to_version)] = True

    @classmethod
    def is_approved(cls, from_version: str, to_version: str) -> bool:
        return cls.APPROVED_TRANSITIONS.get((from_version, to_version), False)

    @classmethod
    def require_approved(cls, from_version: str, to_version: str) -> None:
        if not cls.is_approved(from_version, to_version):
            raise RuntimeCompatibilityError(
                f"Replay from {from_version} to {to_version} not approved. "
                f"Use approve_transition() to whitelist."
            )


class RuntimeCompatibilityError(Exception):
    """Raised when cross-version replay is blocked by compatibility fence."""


# ──────────────────────────────
#  Replay Hydrator
# ──────────────────────────────

@dataclass(frozen=True)
class HydrationResult:
    """Result of hydrating a historical event to a target schema."""

    event_id: str
    original_fingerprint: str
    target_fingerprint: str
    hydrated_payload: Dict[str, Any]
    hydration_path: List[str]
    deterministic: bool
    errors: List[str]
    hydration_hash: str = ""

    def __post_init__(self, _: Any = None) -> None:
        if not self.hydration_hash:
            hydration_json = json.dumps(self.hydrated_payload, sort_keys=True, default=str, separators=(",", ":"))
            object.__setattr__(self, "hydration_hash", hashlib.sha256(hydration_json.encode()).hexdigest())


class ReplayHydrator:
    """Deterministic event hydration across schema versions.

    Uses explicit migration paths from SchemaRegistry.
    No automatic inference. No probabilistic field mapping.
    """

    def __init__(self, schema_registry: SchemaRegistry) -> None:
        self.schema_registry = schema_registry

    def hydrate_event(
        self,
        event: DomainEvent,
        target_schema: ArtifactSchema,
        context: VersionedReplayContext,
    ) -> HydrationResult:
        """Hydrate a single historical event to a target schema.

        Returns HydrationResult with deterministic hash of the hydrated data.
        """
        # Verify runtime compatibility
        RuntimeCompatibilityFence.require_approved(
            context.source_runtime_version,
            context.target_runtime_version,
        )

        # Extract original schema fingerprint from event payload
        original_fp = event.payload.get("schema_fingerprint", "")
        if not original_fp:
            return HydrationResult(
                event_id=event.header.event_id,
                original_fingerprint="",
                target_fingerprint=target_schema.fingerprint.value,
                hydrated_payload=dict(event.payload),
                hydration_path=[],
                deterministic=True,
                errors=["no_schema_fingerprint_in_payload"],
                hydration_hash="",
            )

        # Find migration path
        path = self.schema_registry.find_migration_path(
            original_fp, target_schema.fingerprint.value
        )

        if not path:
            return HydrationResult(
                event_id=event.header.event_id,
                original_fingerprint=original_fp,
                target_fingerprint=target_schema.fingerprint.value,
                hydrated_payload=dict(event.payload),
                hydration_path=[],
                deterministic=True,
                errors=[f"no_migration_path: {original_fp} -> {target_schema.fingerprint.value}"],
                hydration_hash="",
            )

        # Apply migrations
        migrated, errors = self.schema_registry.migrate_data_safe(
            event.payload,
            original_fp,
            target_schema.fingerprint.value,
            direction="forward",
        )

        # Compute deterministic hydration hash
        hydration_json = json.dumps(migrated, sort_keys=True, default=str, separators=(",", ":"))
        hydration_hash = hashlib.sha256(hydration_json.encode()).hexdigest()

        return HydrationResult(
            event_id=event.header.event_id,
            original_fingerprint=original_fp,
            target_fingerprint=target_schema.fingerprint.value,
            hydrated_payload=migrated,
            hydration_path=[step.migration_id for step in path],
            deterministic=len(errors) == 0,
            errors=errors,
            hydration_hash=hydration_hash,
        )

    def hydrate_partition(
        self,
        partition_key: str,
        target_schema: ArtifactSchema,
        context: VersionedReplayContext,
        storage: EventBusStorage,
        start_offset: int = 1,
        end_offset: Optional[int] = None,
    ) -> Tuple[List[HydrationResult], Dict[str, Any]]:
        """Hydrate all events in a partition range to a target schema.

        Returns (results, summary).
        """
        replay_engine = EventReplayEngine(storage)
        events = list(replay_engine.replay_partition(partition_key, start_offset, end_offset))

        results: List[HydrationResult] = []
        success_count = 0
        error_count = 0

        for event in events:
            result = self.hydrate_event(event, target_schema, context)
            results.append(result)
            if result.errors:
                error_count += 1
            else:
                success_count += 1

        summary = {
            "partition_key": partition_key,
            "source_runtime": context.source_runtime_version,
            "target_runtime": context.target_runtime_version,
            "target_schema": target_schema.fingerprint.value,
            "total_events": len(events),
            "success_count": success_count,
            "error_count": error_count,
            "epoch": context.epoch_number,
            "read_only": context.read_only,
        }

        return results, summary


# ──────────────────────────────
#  Cross-Version Replay Report
# ──────────────────────────────

@dataclass(frozen=True)
class CrossVersionReplayReport:
    """Deterministic summary of cross-version replay operation."""

    replay_id: str
    context: VersionedReplayContext
    summary: Dict[str, Any]
    hydration_results: List[HydrationResult]
    chain_integrity_verified: bool
    report_hash: str

    def __post_init__(self, _: Any = None) -> None:
        if not self.report_hash:
            data = json.dumps({
                "replay_id": self.replay_id,
                "context": self.context.to_dict(),
                "summary": self.summary,
            }, sort_keys=True, default=str, separators=(",", ":"))
            object.__setattr__(self, "report_hash", hashlib.sha256(data.encode()).hexdigest())


class CrossVersionReplayEngine:
    """High-level engine for cross-version replay with full provenance.

    Combines EventBus, SchemaRegistry, and RuntimeCompatibilityFence
to produce deterministic, auditable replay results.
    """

    def __init__(
        self,
        event_storage: EventBusStorage,
        schema_registry: SchemaRegistry,
        hydrator: ReplayHydrator,
    ) -> None:
        self.event_storage = event_storage
        self.schema_registry = schema_registry
        self.hydrator = hydrator

    def replay(
        self,
        partition_key: str,
        target_schema: ArtifactSchema,
        context: VersionedReplayContext,
        start_offset: int = 1,
        end_offset: Optional[int] = None,
    ) -> CrossVersionReplayReport:
        """Execute cross-version replay with full provenance.

        All parameters are frozen. Result is deterministic.
        """
        # Verify chain integrity before replay
        integrity_ok, integrity_errors = self.event_storage.verify_partition_chain(partition_key)

        # Hydrate events
        results, summary = self.hydrator.hydrate_partition(
            partition_key, target_schema, context, self.event_storage, start_offset, end_offset,
        )

        # Build report
        report = CrossVersionReplayReport(
            replay_id=f"replay_{context.replay_correlation_id}_{partition_key}_{start_offset}",
            context=context,
            summary=summary,
            hydration_results=results,
            chain_integrity_verified=integrity_ok and len(integrity_errors) == 0,
            report_hash="",
        )

        return report
