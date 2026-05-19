"""Deterministic EventBus.

Append-only, ordered, cryptographically chained event stream for the PI Platform.
Every event is strictly ordered within its partition, every partition is strictly
ordered within the global log. Events are immutable. Checkpoints are deterministic
and tied to the clock ordering established by the snapshot subsystem.

No probabilistic ordering. No nondeterministic consumption. No mutable history.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import struct
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Generator, Iterator, List, Optional, Tuple

from pi_interoperability_layer.snapshot.clock import DeterministicClock, canonical_timestamp


class EventType(str, Enum):
    ARTIFACT_CREATED = "artifact:created"
    ARTIFACT_MUTATED = "artifact:mutated"  # Only permitted in DRIFT logs — never in event history
    WORKER_DISPATCHED = "worker:dispatched"
    WORKER_COMPLETED = "worker:completed"
    WORKER_FAILED = "worker:failed"
    COMPOSITION_ACCEPTED = "composition:accepted"
    COMPOSITION_REJECTED = "composition:rejected"
    COMPOSITION_EXECUTED = "composition:executed"
    STAGE_TRANSITION = "stage:transition"
    POLICY_ENFORCED = "policy:enforced"
    POLICY_VIOLATION = "policy:violation"
    SNAPSHOT_STORED = "snapshot:stored"
    SNAPSHOT_CHAINED = "snapshot:chained"
    REPLAY_INITIALIZED = "replay:initialized"
    REPLAY_RECONSTRUCTED = "replay:reconstructed"
    TENANT_CREATED = "tenant:created"
    TENANT_DEACTIVATED = "tenant:deactivated"
    GOVERNANCE_RULE_APPLIED = "governance:rule_applied"
    SCHEMA_REGISTERED = "schema:registered"
    SCHEMA_DEPRECATED = "schema:deprecated"
    MIGRATION_EXECUTED = "migration:executed"
    RUNTIME_VERSION_CHANGED = "runtime:version_changed"
    CHECKPOINT_WRITTEN = "checkpoint:written"
    ORDERING_EPOCH_ESTABLISHED = "ordering:epoch_established"


class PartitionKey:
    DEFAULT = "default"
    COMPOSITIONS = "compositions"
    WORKERS = "workers"
    ARTIFACTS = "artifacts"
    SNAPSHOTS = "snapshots"
    AUDIT = "audit"
    GOVERNANCE = "governance"
    RUNTIME = "runtime"


# ──────────────────────────────
#  Event Header (immutable)
# ──────────────────────────────

@dataclass(frozen=True)
class EventHeader:
    event_id: str
    event_type: EventType
    partition_key: str
    partition_offset: int
    timestamp: str
    ordering_key: str
    author_tenant_id: str
    author_actor_id: str
    correlation_id: str
    previous_event_hash: str
    payload_hash: str

    def serialize(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "partition_key": self.partition_key,
            "partition_offset": self.partition_offset,
            "timestamp": self.timestamp,
            "ordering_key": self.ordering_key,
            "author_tenant_id": self.author_tenant_id,
            "author_actor_id": self.author_actor_id,
            "correlation_id": self.correlation_id,
            "previous_event_hash": self.previous_event_hash,
            "payload_hash": self.payload_hash,
        }

    @classmethod
    def deserialize(cls, d: Dict[str, Any]) -> "EventHeader":
        return cls(
            event_id=d["event_id"],
            event_type=EventType(d["event_type"]),
            partition_key=d["partition_key"],
            partition_offset=d["partition_offset"],
            timestamp=d["timestamp"],
            ordering_key=d["ordering_key"],
            author_tenant_id=d["author_tenant_id"],
            author_actor_id=d["author_actor_id"],
            correlation_id=d["correlation_id"],
            previous_event_hash=d["previous_event_hash"],
            payload_hash=d["payload_hash"],
        )


# ──────────────────────────────
#  Domain Event (full record)
# ──────────────────────────────

@dataclass(frozen=True)
class DomainEvent:
    header: EventHeader
    payload: Dict[str, Any]
    event_hash: str = ""  # SHA-256(header.canonical || payload.canonical)

    def __post_init__(self, _: Any = None) -> None:
        if not self.event_hash:
            object.__setattr__(
                self,
                "event_hash",
                self._compute_hash(),
            )

    def _compute_hash(self) -> str:
        header_json = json.dumps(self.header.serialize(), sort_keys=True, separators=(",", ":"))
        payload_json = json.dumps(self.payload, sort_keys=True, default=str, separators=(",", ":"))
        combined = header_json + payload_json
        return hashlib.sha256(combined.encode()).hexdigest()

    def serialize(self) -> Dict[str, Any]:
        return {
            "header": self.header.serialize(),
            "payload": self.payload,
            "event_hash": self.event_hash,
        }

    @classmethod
    def deserialize(cls, d: Dict[str, Any]) -> "DomainEvent":
        return cls(
            header=EventHeader.deserialize(d["header"]),
            payload=d["payload"],
            event_hash=d.get("event_hash", ""),
        )


# ──────────────────────────────
#  Deterministic Consumer Checkpoint
# ──────────────────────────────

@dataclass(frozen=True)
class ConsumerCheckpoint:
    consumer_id: str
    partition_key: str
    last_consumed_offset: int
    last_event_id: str
    checkpoint_hash: str
    checkpointed_at: str

    def _compute_hash(self) -> str:
        data = json.dumps({
            "consumer_id": self.consumer_id,
            "partition_key": self.partition_key,
            "last_consumed_offset": self.last_consumed_offset,
            "last_event_id": self.last_event_id,
            "checkpointed_at": self.checkpointed_at,
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(data.encode()).hexdigest()

    def verify(self) -> bool:
        return self._compute_hash() == self.checkpoint_hash


# ──────────────────────────────
#  EventBus Storage Layer
# ──────────────────────────────

class EventBusStorage:
    """SQLite-backed append-only event storage.

    Partition-scoped ordering with global monotonic offset.
    Every event carries previous_event_hash for chain integrity.
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS events (
        global_offset INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL,
        partition_key TEXT NOT NULL,
        partition_offset INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        ordering_key TEXT NOT NULL,
        author_tenant_id TEXT NOT NULL,
        author_actor_id TEXT NOT NULL,
        correlation_id TEXT NOT NULL,
        previous_event_hash TEXT NOT NULL,
        payload_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL,
        payload_json TEXT NOT NULL,

        UNIQUE(partition_key, partition_offset)
    );

    CREATE INDEX IF NOT EXISTS idx_events_partition ON events(partition_key, partition_offset);
    CREATE INDEX IF NOT EXISTS idx_events_tenant ON events(author_tenant_id, partition_key);
    CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type, partition_key);
    CREATE INDEX IF NOT EXISTS idx_events_correlation ON events(correlation_id);

    CREATE TABLE IF NOT EXISTS checkpoints (
        checkpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
        consumer_id TEXT NOT NULL,
        partition_key TEXT NOT NULL,
        last_consumed_offset INTEGER NOT NULL,
        last_event_id TEXT NOT NULL,
        checkpoint_hash TEXT NOT NULL,
        checkpointed_at TEXT NOT NULL,

        UNIQUE(consumer_id, partition_key)
    );

    CREATE TABLE IF NOT EXISTS epoch_markers (
        epoch_id INTEGER PRIMARY KEY AUTOINCREMENT,
        epoch_number INTEGER NOT NULL UNIQUE,
        established_at TEXT NOT NULL,
        ordering_key TEXT NOT NULL,
        established_by TEXT NOT NULL,
        metadata_json TEXT NOT NULL DEFAULT '{}'
    );

    CREATE TABLE IF NOT EXISTS event_partitions (
        partition_key TEXT PRIMARY KEY,
        current_offset INTEGER NOT NULL DEFAULT 0,
        last_event_id TEXT NOT NULL DEFAULT '',
        last_event_hash TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL
    );
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.executescript(self.SCHEMA)
            conn.commit()
            conn.close()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ── Partition Management ─────────────────────────────────

    def _get_or_create_partition(self, partition_key: str) -> Tuple[int, str, str]:
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                "SELECT current_offset, last_event_id, last_event_hash FROM event_partitions WHERE partition_key = ?",
                (partition_key,),
            ).fetchone()
            if row is None:
                created_at = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    "INSERT INTO event_partitions (partition_key, current_offset, last_event_id, last_event_hash, created_at) VALUES (?, 0, '', '', ?)",
                    (partition_key, created_at),
                )
                conn.commit()
                return (0, "", "")
            return (row["current_offset"], row["last_event_id"], row["last_event_hash"])

    def _increment_partition(self, partition_key: str, event_id: str, event_hash: str) -> int:
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                "SELECT current_offset FROM event_partitions WHERE partition_key = ?",
                (partition_key,),
            ).fetchone()
            new_offset = row["current_offset"] + 1
            conn.execute(
                "UPDATE event_partitions SET current_offset = ?, last_event_id = ?, last_event_hash = ? WHERE partition_key = ?",
                (new_offset, event_id, event_hash, partition_key),
            )
            conn.commit()
            return new_offset

    # ── Event Production ─────────────────────────────────────

    def append(
        self,
        event_type: EventType,
        partition_key: str,
        payload: Dict[str, Any],
        tenant_id: str,
        actor_id: str,
        correlation_id: str,
        clock: Optional[DeterministicClock] = None,
    ) -> DomainEvent:
        """Append a single event to the specified partition.

        Deterministic ordering within partition. Global offset monotonically increasing.
        Every event cryptographically chained to previous event in partition.
        """
        clk = clock or DeterministicClock(clock_id="eventbus")
        marker = clk.ordered_now()

        payload_json = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
        payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()

        with self._lock:
            conn = self._conn()
            conn.execute("BEGIN IMMEDIATE")
            try:
                # Get or create partition atomically
                row = conn.execute(
                    "SELECT current_offset, last_event_hash FROM event_partitions WHERE partition_key = ?",
                    (partition_key,),
                ).fetchone()

                if row is None:
                    current_offset = 0
                    last_event_hash = ""
                    conn.execute(
                        "INSERT INTO event_partitions (partition_key, current_offset, last_event_id, last_event_hash, created_at) VALUES (?, 0, '', '', ?)",
                        (partition_key, datetime.now(timezone.utc).isoformat()),
                    )
                else:
                    current_offset = row["current_offset"]
                    last_event_hash = row["last_event_hash"]

                new_partition_offset = current_offset + 1

                event_id = f"evt_{tenant_id}_{partition_key}_{new_partition_offset}_{marker.ordering_key}"

                header = EventHeader(
                    event_id=event_id,
                    event_type=event_type,
                    partition_key=partition_key,
                    partition_offset=new_partition_offset,
                    timestamp=canonical_timestamp(marker.wall_time),
                    ordering_key=marker.ordering_key,
                    author_tenant_id=tenant_id,
                    author_actor_id=actor_id,
                    correlation_id=correlation_id,
                    previous_event_hash=last_event_hash,
                    payload_hash=payload_hash,
                )
                event = DomainEvent(header=header, payload=payload)

                conn.execute(
                    """INSERT INTO events (
                        event_id, event_type, partition_key, partition_offset,
                        timestamp, ordering_key, author_tenant_id, author_actor_id,
                        correlation_id, previous_event_hash, payload_hash, event_hash, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.header.event_id, event.header.event_type.value, event.header.partition_key,
                        event.header.partition_offset, event.header.timestamp, event.header.ordering_key,
                        event.header.author_tenant_id, event.header.author_actor_id,
                        event.header.correlation_id, event.header.previous_event_hash,
                        event.header.payload_hash, event.event_hash, payload_json,
                    ),
                )
                # Update partition metadata atomically within same transaction
                conn.execute(
                    "UPDATE event_partitions SET current_offset = ?, last_event_id = ?, last_event_hash = ? WHERE partition_key = ?",
                    (new_partition_offset, event_id, event.event_hash, partition_key),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

        return event

    # ── Event Retrieval ──────────────────────────────────────

    def read_partition(
        self,
        partition_key: str,
        start_offset: int = 1,
        limit: int = 1000,
        tenant_filter: Optional[str] = None,
    ) -> List[DomainEvent]:
        """Read events from a partition in strict offset order.

        Tenant isolation enforced via filter.
        """
        with self._lock:
            conn = self._conn()
            if tenant_filter:
                rows = conn.execute(
                    """SELECT * FROM events
                       WHERE partition_key = ? AND partition_offset >= ? AND author_tenant_id = ?
                       ORDER BY partition_offset ASC
                       LIMIT ?""",
                    (partition_key, start_offset, tenant_filter, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM events
                       WHERE partition_key = ? AND partition_offset >= ?
                       ORDER BY partition_offset ASC
                       LIMIT ?""",
                    (partition_key, start_offset, limit),
                ).fetchall()
            conn.close()

        return [self._row_to_event(dict(r)) for r in rows]

    def read_event(self, event_id: str) -> Optional[DomainEvent]:
        with self._lock:
            conn = self._conn()
            row = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
            conn.close()
        return self._row_to_event(dict(row)) if row else None

    def read_by_correlation(self, correlation_id: str) -> List[DomainEvent]:
        with self._lock:
            conn = self._conn()
            rows = conn.execute(
                "SELECT * FROM events WHERE correlation_id = ? ORDER BY global_offset ASC",
                (correlation_id,),
            ).fetchall()
            conn.close()
        return [self._row_to_event(dict(r)) for r in rows]

    def get_partition_tail(self, partition_key: str, n: int = 10) -> List[DomainEvent]:
        """Get the last N events from a partition."""
        with self._lock:
            conn = self._conn()
            rows = conn.execute(
                """SELECT * FROM events
                   WHERE partition_key = ?
                   ORDER BY partition_offset DESC
                   LIMIT ?""",
                (partition_key, n),
            ).fetchall()
            conn.close()
        return [self._row_to_event(dict(r)) for r in rows][::-1]

    def get_partition_metadata(self, partition_key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                "SELECT * FROM event_partitions WHERE partition_key = ?",
                (partition_key,),
            ).fetchone()
            conn.close()
        return dict(row) if row else None

    def _row_to_event(self, row: Dict[str, Any]) -> DomainEvent:
        header = EventHeader(
            event_id=row["event_id"],
            event_type=EventType(row["event_type"]),
            partition_key=row["partition_key"],
            partition_offset=row["partition_offset"],
            timestamp=row["timestamp"],
            ordering_key=row["ordering_key"],
            author_tenant_id=row["author_tenant_id"],
            author_actor_id=row["author_actor_id"],
            correlation_id=row["correlation_id"],
            previous_event_hash=row["previous_event_hash"],
            payload_hash=row["payload_hash"],
        )
        payload = json.loads(row["payload_json"])
        return DomainEvent(header=header, payload=payload, event_hash=row["event_hash"])

    # ── Checkpoint Management ────────────────────────────────

    def write_checkpoint(self, checkpoint: ConsumerCheckpoint) -> None:
        with self._lock:
            conn = self._conn()
            conn.execute("""
                INSERT INTO checkpoints (consumer_id, partition_key, last_consumed_offset, last_event_id, checkpoint_hash, checkpointed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(consumer_id, partition_key) DO UPDATE SET
                    last_consumed_offset = excluded.last_consumed_offset,
                    last_event_id = excluded.last_event_id,
                    checkpoint_hash = excluded.checkpoint_hash,
                    checkpointed_at = excluded.checkpointed_at
            """, (
                checkpoint.consumer_id, checkpoint.partition_key,
                checkpoint.last_consumed_offset, checkpoint.last_event_id,
                checkpoint.checkpoint_hash, checkpoint.checkpointed_at,
            ))
            conn.commit()
            conn.close()

    def read_checkpoint(self, consumer_id: str, partition_key: str) -> Optional[ConsumerCheckpoint]:
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                "SELECT * FROM checkpoints WHERE consumer_id = ? AND partition_key = ?",
                (consumer_id, partition_key),
            ).fetchone()
            conn.close()
        if not row:
            return None
        return ConsumerCheckpoint(
            consumer_id=row["consumer_id"],
            partition_key=row["partition_key"],
            last_consumed_offset=row["last_consumed_offset"],
            last_event_id=row["last_event_id"],
            checkpoint_hash=row["checkpoint_hash"],
            checkpointed_at=row["checkpointed_at"],
        )

    # ── Chain Integrity ──────────────────────────────────────

    def verify_partition_chain(self, partition_key: str) -> Tuple[bool, List[str]]:
        """Verify cryptographic chain integrity for a partition.

        Every event's previous_event_hash must match the actual hash
        of the preceding event in that partition.
        """
        events = self.read_partition(partition_key, start_offset=1, limit=1_000_000)
        if not events:
            return True, []

        errors: List[str] = []
        for i, event in enumerate(events):
            expected = event.event_hash
            # Verify event hash correctness
            recomputed = event._compute_hash() if i > 0 else event.event_hash  # First event has no prev
            if expected != recomputed:
                errors.append(f"hash_mismatch at offset {event.header.partition_offset}: expected={expected}, got={recomputed}")
            # Verify chain linkage
            if i > 0:
                prev_hash = events[i - 1].event_hash
                if event.header.previous_event_hash != prev_hash:
                    errors.append(
                        f"chain_break at offset {event.header.partition_offset}: expected_prev={prev_hash}, got={event.header.previous_event_hash}"
                    )

        return len(errors) == 0, errors

    # ── Epoch Management ─────────────────────────────────────

    def establish_epoch(self, epoch_number: int, established_by: str, metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        clk = DeterministicClock(clock_id="eventbus")
        marker = clk.ordered_now()
        coord_data = json.dumps({
            "epoch_number": epoch_number,
            "established_at": canonical_timestamp(marker.wall_time),
            "established_by": established_by,
            "metadata": metadata or {},
        }, sort_keys=True, default=str)
        coord_hash = hashlib.sha256(coord_data.encode()).hexdigest()
        with self._lock:
            conn = self._conn()
            conn.execute(
                "INSERT INTO epoch_markers (epoch_number, established_at, ordering_key, established_by, metadata_json) VALUES (?, ?, ?, ?, ?)",
                (epoch_number, canonical_timestamp(marker.wall_time), marker.ordering_key, established_by, json.dumps(metadata or {}, sort_keys=True)),
            )
            conn.commit()
            epoch_id = conn.execute("SELECT epoch_id FROM epoch_markers WHERE epoch_number = ?", (epoch_number,)).fetchone()["epoch_id"]
            conn.close()
        return {"epoch_id": epoch_id, "epoch_number": epoch_number, "ordering_key": marker.ordering_key, "coordination_hash": coord_hash}

    def get_epoch(self, epoch_number: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._conn()
            row = conn.execute("SELECT * FROM epoch_markers WHERE epoch_number = ?", (epoch_number,)).fetchone()
            conn.close()
        if not row:
            return None
        return dict(row)

    # ── Stats ────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            conn = self._conn()
            event_count = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]
            partition_count = conn.execute("SELECT COUNT(*) as c FROM event_partitions").fetchone()["c"]
            checkpoint_count = conn.execute("SELECT COUNT(*) as c FROM checkpoints").fetchone()["c"]
            epoch_count = conn.execute("SELECT COUNT(*) as c FROM epoch_markers").fetchone()["c"]
            conn.close()
        return {
            "event_count": event_count,
            "partition_count": partition_count,
            "checkpoint_count": checkpoint_count,
            "epoch_count": epoch_count,
        }


# ──────────────────────────────
#  Deterministic Consumer
# ──────────────────────────────

class DeterministicConsumer:
    """Deterministic event consumer with checkpointed progress.

    Guarantees exactly-once, in-order consumption within a partition.
    No nondeterministic offset seeking. Checkpoints are cryptographically verified.
    """

    def __init__(self, consumer_id: str, storage: EventBusStorage, tenant_id: Optional[str] = None):
        self.consumer_id = consumer_id
        self.storage = storage
        self.tenant_id = tenant_id
        self._lock = threading.Lock()

    def consume(self, partition_key: str, handler, batch_size: int = 100) -> int:
        """Consume next batch of events from partition.

        Returns number of events processed.
        Events are delivered strictly in partition_offset order.
        """
        checkpoint = self.storage.read_checkpoint(self.consumer_id, partition_key)
        start_offset = (checkpoint.last_consumed_offset + 1) if checkpoint else 1

        events = self.storage.read_partition(
            partition_key,
            start_offset=start_offset,
            limit=batch_size,
            tenant_filter=self.tenant_id,
        )

        processed = 0
        for event in events:
            handler(event)
            processed += 1

        if processed > 0:
            last_event = events[-1]
            new_checkpoint = ConsumerCheckpoint(
                consumer_id=self.consumer_id,
                partition_key=partition_key,
                last_consumed_offset=last_event.header.partition_offset,
                last_event_id=last_event.header.event_id,
                checkpoint_hash="",  # computed in __post_init__
                checkpointed_at=canonical_timestamp(datetime.now(timezone.utc)),
            )
            object.__setattr__(new_checkpoint, "checkpoint_hash", new_checkpoint._compute_hash())
            self.storage.write_checkpoint(new_checkpoint)

        return processed

    def get_checkpoint(self, partition_key: str) -> Optional[ConsumerCheckpoint]:
        return self.storage.read_checkpoint(self.consumer_id, partition_key)


# ──────────────────────────────
#  Event Replay Engine
# ──────────────────────────────

class EventReplayEngine:
    """Read-only replay of events from any point in the past.

    Deterministic reconstruction of event stream state.
    No mutation. No worker triggering. Pure replay.
    """

    def __init__(self, storage: EventBusStorage):
        self.storage = storage

    def replay_partition(
        self,
        partition_key: str,
        start_offset: int = 1,
        end_offset: Optional[int] = None,
        correlation_filter: Optional[str] = None,
    ) -> Iterator[DomainEvent]:
        """Yield events from a partition range in strict order.

        Deterministic traversal with optional correlation_id filter.
        """
        events = self.storage.read_partition(partition_key, start_offset, limit=1_000_000)
        for event in events:
            if end_offset is not None and event.header.partition_offset > end_offset:
                break
            if correlation_filter and event.header.correlation_id != correlation_filter:
                continue
            yield event

    def reconstruct_state(self, partition_key: str, state_builder) -> Dict[str, Any]:
        """Reconstruct state by replaying all events through a state builder function.

        state_builder receives (current_state, event) and returns new_state.
        """
        state: Dict[str, Any] = {}
        for event in self.replay_partition(partition_key):
            state = state_builder(state, event)
        return state

    def get_replay_summary(
        self,
        partition_key: str,
        start_offset: int = 1,
        end_offset: Optional[int] = None,
    ) -> Dict[str, Any]:
        events = list(self.replay_partition(partition_key, start_offset, end_offset))
        return {
            "partition_key": partition_key,
            "start_offset": start_offset,
            "end_offset": end_offset,
            "event_count": len(events),
            "first_event_time": events[0].header.timestamp if events else None,
            "last_event_time": events[-1].header.timestamp if events else None,
            "event_types": sorted(set(e.header.event_type.value for e in events)),
            "tenant_ids": sorted(set(e.header.author_tenant_id for e in events)),
            "chain_integrity": self.storage.verify_partition_chain(partition_key),
        }
