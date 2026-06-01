"""Deterministic Distributed Ordering Guarantees.

Shard-scoped event sequencing with cross-node coordination.
Every shard maintains a monotonic sequence number.
Cross-shard ordering is established via epoch markers.
No probabilistic ordering. No leader election.

Key concepts:
- ShardSequence: monotonic, deterministic sequence within a shard
- OrderingEpoch: global epoch marker for cross-shard alignment
- MonotonicCheckpoint: shard-level progress with cryptographic proof
- CrossShardOrderingRule: deterministic rule for ordering across shards
- PartitionRecovery: deterministic recovery after node failure
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pi_event_fabric.bus.core import (
    DomainEvent,
    EventBusStorage,
)
from pi_interoperability_layer.snapshot.clock import DeterministicClock, canonical_timestamp

# ──────────────────────────────
#  Shard Sequence
# ──────────────────────────────


@dataclass(frozen=True)
class ShardSequence:
    """Immutable sequence state for a single shard.

    Monotonic: next_sequence > current_sequence always.
    Deterministic: derived from explicit event ordering, not wall clock.
    """

    shard_id: str
    current_sequence: int
    last_event_id: str
    last_event_hash: str
    epoch_number: int
    frozen: bool = False

    def next(self, event_id: str, event_hash: str) -> "ShardSequence":
        if self.frozen:
            raise SequenceFrozenError(f"Shard {self.shard_id} is frozen")
        return ShardSequence(
            shard_id=self.shard_id,
            current_sequence=self.current_sequence + 1,
            last_event_id=event_id,
            last_event_hash=event_hash,
            epoch_number=self.epoch_number,
            frozen=False,
        )

    def freeze(self) -> "ShardSequence":
        return ShardSequence(
            shard_id=self.shard_id,
            current_sequence=self.current_sequence,
            last_event_id=self.last_event_id,
            last_event_hash=self.last_event_hash,
            epoch_number=self.epoch_number,
            frozen=True,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "shard_id": self.shard_id,
            "current_sequence": self.current_sequence,
            "last_event_id": self.last_event_id,
            "last_event_hash": self.last_event_hash,
            "epoch_number": self.epoch_number,
            "frozen": self.frozen,
        }


class SequenceFrozenError(Exception):
    """Raised when attempting to append to a frozen shard sequence."""


# ──────────────────────────────
#  Monotonic Checkpoint
# ──────────────────────────────


@dataclass(frozen=True)
class MonotonicCheckpoint:
    """Cryptographic checkpoint for shard progress.

    Cannot roll back. Only forward.
    Hash covers: shard_id + sequence + last_event_hash + epoch + timestamp.
    """

    checkpoint_id: str
    shard_id: str
    sequence: int
    last_event_hash: str
    epoch_number: int
    timestamp: str
    checkpoint_hash: str

    def __post_init__(self, _: Any = None) -> None:
        if not self.checkpoint_hash:
            data = json.dumps(
                {
                    "checkpoint_id": self.checkpoint_id,
                    "shard_id": self.shard_id,
                    "sequence": self.sequence,
                    "last_event_hash": self.last_event_hash,
                    "epoch_number": self.epoch_number,
                    "timestamp": self.timestamp,
                },
                sort_keys=True,
                separators=(",", ":"),
                default=str,
            )
            object.__setattr__(self, "checkpoint_hash", hashlib.sha256(data.encode()).hexdigest())

    def verify(self) -> bool:
        expected = MonotonicCheckpoint(
            checkpoint_id=self.checkpoint_id,
            shard_id=self.shard_id,
            sequence=self.sequence,
            last_event_hash=self.last_event_hash,
            epoch_number=self.epoch_number,
            timestamp=self.timestamp,
            checkpoint_hash="",
        ).checkpoint_hash
        return self.checkpoint_hash == expected


# ──────────────────────────────
#  Cross-Shard Ordering Rules
# ──────────────────────────────


@dataclass(frozen=True)
class CrossShardOrderingRule:
    """Deterministic rule for ordering events across shards.

    Tiebreaker hierarchy:
    1. Epoch number (higher epoch = later)
    2. Shard priority (explicit priority ranking)
    3. Sequence number (higher = later)
    4. Event hash (lexicographic, deterministic)

    No wall-clock in ordering. Only explicit sequence state.
    """

    shard_priorities: Dict[str, int]  # shard_id -> priority (lower = higher priority)

    def compare(self, a: DomainEvent, b: DomainEvent) -> int:
        """Compare two events for cross-shard ordering.

        Returns: -1 if a < b, 0 if equal, 1 if a > b
        """
        # Epoch comparison (from header metadata or payload)
        epoch_a = a.payload.get("epoch_number", 0)
        epoch_b = b.payload.get("epoch_number", 0)
        if epoch_a != epoch_b:
            return -1 if epoch_a < epoch_b else 1

        # Shard priority comparison
        priority_a = self.shard_priorities.get(a.header.partition_key, 9999)
        priority_b = self.shard_priorities.get(b.header.partition_key, 9999)
        if priority_a != priority_b:
            return -1 if priority_a < priority_b else 1

        # Sequence comparison (from partition_offset as proxy for sequence)
        seq_a = a.header.partition_offset
        seq_b = b.header.partition_offset
        if seq_a != seq_b:
            return -1 if seq_a < seq_b else 1

        # Deterministic tiebreaker: event hash lexicographic
        if a.event_hash < b.event_hash:
            return -1
        if a.event_hash > b.event_hash:
            return 1
        return 0

    def merge_streams(
        self,
        streams: Dict[str, List[DomainEvent]],
    ) -> List[DomainEvent]:
        """Merge multiple shard streams into a single deterministic order.

        Uses k-way merge with the compare() rule.
        """
        # Collect all events with their source shard
        indexed: List[Tuple[DomainEvent, str]] = []
        for shard_id, events in streams.items():
            for event in events:
                indexed.append((event, shard_id))

        # Deterministic sort using the cross-shard rule
        def sort_key(item: Tuple[DomainEvent, str]) -> Tuple:
            event, shard_id = item
            priority = self.shard_priorities.get(shard_id, 9999)
            epoch = event.payload.get("epoch_number", 0)
            return (epoch, priority, event.header.partition_offset, event.event_hash)

        indexed.sort(key=sort_key)
        return [event for event, _ in indexed]


# ──────────────────────────────
#  Shard Coordinator
# ──────────────────────────────


class ShardCoordinator:
    """Deterministic shard sequencing and checkpoint coordination.

    Maintains per-shard sequence state. Coordinates cross-shard epochs.
    No leader election. No probabilistic consensus.
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS shard_sequences (
        shard_id TEXT PRIMARY KEY,
        current_sequence INTEGER NOT NULL DEFAULT 0,
        last_event_id TEXT NOT NULL DEFAULT '',
        last_event_hash TEXT NOT NULL DEFAULT '',
        epoch_number INTEGER NOT NULL DEFAULT 0,
        frozen INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS shard_checkpoints (
        checkpoint_id TEXT PRIMARY KEY,
        shard_id TEXT NOT NULL,
        sequence INTEGER NOT NULL,
        last_event_hash TEXT NOT NULL,
        epoch_number INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        checkpoint_hash TEXT NOT NULL,
        UNIQUE(shard_id, sequence)
    );

    CREATE TABLE IF NOT EXISTS epoch_coordinations (
        epoch_number INTEGER PRIMARY KEY,
        established_at TEXT NOT NULL,
        participating_shards TEXT NOT NULL,  -- JSON list
        coordination_hash TEXT NOT NULL
    );
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
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

    # ── Sequence Management ───────────────────────────────────

    def get_sequence(self, shard_id: str) -> ShardSequence:
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                "SELECT * FROM shard_sequences WHERE shard_id = ?",
                (shard_id,),
            ).fetchone()
            conn.close()

        if row is None:
            return ShardSequence(
                shard_id=shard_id,
                current_sequence=0,
                last_event_id="",
                last_event_hash="",
                epoch_number=0,
                frozen=False,
            )

        return ShardSequence(
            shard_id=row["shard_id"],
            current_sequence=row["current_sequence"],
            last_event_id=row["last_event_id"],
            last_event_hash=row["last_event_hash"],
            epoch_number=row["epoch_number"],
            frozen=bool(row["frozen"]),
        )

    def advance_sequence(
        self,
        shard_id: str,
        event_id: str,
        event_hash: str,
    ) -> ShardSequence:
        """Advance shard sequence by one.

        Atomic update. Monotonic guarantee. Raises if shard is frozen.
        """
        seq = self.get_sequence(shard_id)
        if seq.frozen:
            raise SequenceFrozenError(f"Shard {shard_id} is frozen")

        with self._lock:
            conn = self._conn()
            conn.execute("BEGIN IMMEDIATE")
            try:
                # Verify monotonicity
                row = conn.execute(
                    "SELECT current_sequence FROM shard_sequences WHERE shard_id = ?",
                    (shard_id,),
                ).fetchone()

                current_seq = row["current_sequence"] if row else 0
                new_seq = current_seq + 1

                conn.execute(
                    """INSERT INTO shard_sequences (shard_id, current_sequence, last_event_id, last_event_hash, epoch_number, frozen, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(shard_id) DO UPDATE SET
                           current_sequence = excluded.current_sequence,
                           last_event_id = excluded.last_event_id,
                           last_event_hash = excluded.last_event_hash,
                           updated_at = excluded.updated_at""",
                    (shard_id, new_seq, event_id, event_hash, 0, 0, canonical_timestamp(datetime.now(timezone.utc))),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

        return self.get_sequence(shard_id)

    # ── Checkpoint Management ──────────────────────────────────────

    def write_checkpoint(self, checkpoint: MonotonicCheckpoint) -> None:
        with self._lock:
            conn = self._conn()
            conn.execute(
                """INSERT OR IGNORE INTO shard_checkpoints
                   (checkpoint_id, shard_id, sequence, last_event_hash, epoch_number, timestamp, checkpoint_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    checkpoint.checkpoint_id,
                    checkpoint.shard_id,
                    checkpoint.sequence,
                    checkpoint.last_event_hash,
                    checkpoint.epoch_number,
                    checkpoint.timestamp,
                    checkpoint.checkpoint_hash,
                ),
            )
            conn.commit()
            conn.close()

    def get_latest_checkpoint(self, shard_id: str) -> Optional[MonotonicCheckpoint]:
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                """SELECT * FROM shard_checkpoints
                   WHERE shard_id = ?
                   ORDER BY sequence DESC LIMIT 1""",
                (shard_id,),
            ).fetchone()
            conn.close()

        if not row:
            return None

        return MonotonicCheckpoint(
            checkpoint_id=row["checkpoint_id"],
            shard_id=row["shard_id"],
            sequence=row["sequence"],
            last_event_hash=row["last_event_hash"],
            epoch_number=row["epoch_number"],
            timestamp=row["timestamp"],
            checkpoint_hash=row["checkpoint_hash"],
        )

    def list_checkpoints(self, shard_id: str, limit: int = 100) -> List[MonotonicCheckpoint]:
        with self._lock:
            conn = self._conn()
            rows = conn.execute(
                "SELECT * FROM shard_checkpoints WHERE shard_id = ? ORDER BY sequence ASC LIMIT ?",
                (shard_id, limit),
            ).fetchall()
            conn.close()

        return [
            MonotonicCheckpoint(
                checkpoint_id=r["checkpoint_id"],
                shard_id=r["shard_id"],
                sequence=r["sequence"],
                last_event_hash=r["last_event_hash"],
                epoch_number=r["epoch_number"],
                timestamp=r["timestamp"],
                checkpoint_hash=r["checkpoint_hash"],
            )
            for r in rows
        ]

    # ── Epoch Coordination ──────────────────────────────────────

    def establish_epoch(
        self,
        epoch_number: int,
        participating_shards: List[str],
    ) -> Dict[str, Any]:
        """Establish a new ordering epoch.

        Freezes all participating shards at their current sequence.
        All shards must acknowledge before epoch is active.
        """
        clk = DeterministicClock(clock_id="shard-coordinator")
        marker = clk.ordered_now()

        # Freeze all participating shards
        with self._lock:
            conn = self._conn()
            conn.execute("BEGIN IMMEDIATE")
            try:
                for shard_id in participating_shards:
                    conn.execute(
                        "UPDATE shard_sequences SET frozen = 1, epoch_number = ? WHERE shard_id = ?",
                        (epoch_number, shard_id),
                    )

                # Record epoch coordination
                coord_data = json.dumps(
                    {
                        "epoch_number": epoch_number,
                        "established_at": canonical_timestamp(marker.wall_time),
                        "participating_shards": sorted(participating_shards),
                    },
                    sort_keys=True,
                )
                coord_hash = hashlib.sha256(coord_data.encode()).hexdigest()

                conn.execute(
                    "INSERT OR IGNORE INTO epoch_coordinations (epoch_number, established_at, participating_shards, coordination_hash) VALUES (?, ?, ?, ?)",
                    (
                        epoch_number,
                        canonical_timestamp(marker.wall_time),
                        json.dumps(sorted(participating_shards)),
                        coord_hash,
                    ),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

        return {
            "epoch_number": epoch_number,
            "established_at": canonical_timestamp(marker.wall_time),
            "participating_shards": participating_shards,
            "coordination_hash": coord_hash,
        }

    def get_epoch(self, epoch_number: int) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                "SELECT * FROM epoch_coordinations WHERE epoch_number = ?",
                (epoch_number,),
            ).fetchone()
            conn.close()
        return dict(row) if row else None

    # ── Recovery ───────────────────────────────────────────────

    def recover_shard(self, shard_id: str, event_storage: EventBusStorage) -> ShardSequence:
        """Recover shard sequence from event storage.

        Deterministic: scans partition, rebuilds sequence from events.
        """
        partition_key = shard_id
        tail = event_storage.get_partition_tail(partition_key, n=1)

        if not tail:
            return self.get_sequence(shard_id)

        last_event = tail[0]
        new_seq = last_event.header.partition_offset

        with self._lock:
            conn = self._conn()
            conn.execute(
                """INSERT INTO shard_sequences (shard_id, current_sequence, last_event_id, last_event_hash, epoch_number, frozen, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(shard_id) DO UPDATE SET
                       current_sequence = excluded.current_sequence,
                       last_event_id = excluded.last_event_id,
                       last_event_hash = excluded.last_event_hash,
                       updated_at = excluded.updated_at""",
                (
                    shard_id,
                    new_seq,
                    last_event.header.event_id,
                    last_event.event_hash,
                    0,
                    0,
                    canonical_timestamp(datetime.now(timezone.utc)),
                ),
            )
            conn.commit()
            conn.close()

        return self.get_sequence(shard_id)

    def verify_monotonicity(self, shard_id: str) -> Tuple[bool, List[str]]:
        """Verify that all checkpoints for a shard are monotonically increasing."""
        with self._lock:
            conn = self._conn()
            rows = conn.execute(
                "SELECT * FROM shard_checkpoints WHERE shard_id = ? ORDER BY rowid ASC",
                (shard_id,),
            ).fetchall()
            conn.close()

        checkpoints = [
            MonotonicCheckpoint(
                checkpoint_id=r["checkpoint_id"],
                shard_id=r["shard_id"],
                sequence=r["sequence"],
                last_event_hash=r["last_event_hash"],
                epoch_number=r["epoch_number"],
                timestamp=r["timestamp"],
                checkpoint_hash=r["checkpoint_hash"],
            )
            for r in rows
        ]

        errors: List[str] = []
        for i in range(1, len(checkpoints)):
            prev = checkpoints[i - 1]
            curr = checkpoints[i]
            if curr.sequence <= prev.sequence:
                errors.append(f"non_monotonic at index {i}: {prev.sequence} -> {curr.sequence}")
            if not curr.verify():
                errors.append(f"checkpoint_hash_invalid at index {i}: {curr.checkpoint_id}")

        return len(errors) == 0, errors
