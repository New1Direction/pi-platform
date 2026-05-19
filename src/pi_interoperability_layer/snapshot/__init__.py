"""Snapshot Foundation Layer.

Immutable, append-only SnapshotRegistry and SnapshotArtifact system.
Deterministic, tenant-partitioned, with canonical serialization and
strict clock semantics.

No LLM inference. No probabilistic reasoning. No runtime mutation.
"""

from pi_interoperability_layer.snapshot.artifacts import SnapshotArtifact, SnapshotType
from pi_interoperability_layer.snapshot.registry import SnapshotRegistry
from pi_interoperability_layer.snapshot.clock import DeterministicClock

__all__ = ["SnapshotArtifact", "SnapshotType", "SnapshotRegistry", "DeterministicClock"]
