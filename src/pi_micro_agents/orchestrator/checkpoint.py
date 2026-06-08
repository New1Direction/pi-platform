"""
checkpoint.py — persistent mid-chain state snapshot and resume semantics.

Resume safety: every checkpoint carries a SHA-256 hash of the goal string.
`load(chain_id, current_goal=...)` rejects mismatches so a chain can't resume
into the wrong workflow if the user changed the prompt between runs.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


def goal_hash(goal: str) -> str:
    return hashlib.sha256(goal.strip().encode("utf-8")).hexdigest()


class CheckpointGoalMismatch(RuntimeError):
    """Raised when a resumed checkpoint's goal_hash != the current goal."""


class ChainCheckpoint(BaseModel):
    chain_id: str
    goal: str
    goal_hash: str = ""
    step_index: int
    context_snapshot: Dict[str, Any] = Field(default_factory=dict)
    completed_steps: List[str] = Field(default_factory=list)
    total_steps: int = 0
    created_at: float = Field(default_factory=time.time)
    expires_at: float = Field(default_factory=lambda: time.time() + 3600.0)

    def model_post_init(self, __context: Any) -> None:
        if not self.goal_hash:
            object.__setattr__(self, "goal_hash", goal_hash(self.goal))

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def progress_pct(self) -> float:
        if self.total_steps == 0:
            return 0.0
        return (self.step_index / self.total_steps) * 100.0


class ChainCheckpointManager:
    """SQLite-backed checkpoint store with TTL + goal-hash validation."""

    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, timeout=30.0, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS chain_checkpoints (
                    chain_id TEXT PRIMARY KEY,
                    goal TEXT NOT NULL,
                    goal_hash TEXT NOT NULL,
                    step_index INTEGER NOT NULL,
                    context_snapshot TEXT NOT NULL,
                    completed_steps TEXT NOT NULL,
                    total_steps INTEGER NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_checkpoint_expires
                    ON chain_checkpoints(expires_at);
                """
            )

    def save(self, checkpoint: ChainCheckpoint) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO chain_checkpoints "
                "(chain_id, goal, goal_hash, step_index, context_snapshot, "
                "completed_steps, total_steps, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    checkpoint.chain_id,
                    checkpoint.goal,
                    checkpoint.goal_hash,
                    int(checkpoint.step_index),
                    json.dumps(checkpoint.context_snapshot, default=str),
                    json.dumps(checkpoint.completed_steps),
                    int(checkpoint.total_steps),
                    float(checkpoint.created_at),
                    float(checkpoint.expires_at),
                ),
            )

    def load(self, chain_id: str, current_goal: Optional[str] = None) -> Optional[ChainCheckpoint]:
        """
        Load a checkpoint and validate.

        - Returns None if missing or expired.
        - If current_goal is provided, raises CheckpointGoalMismatch when
          its hash does not match the stored goal_hash.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT chain_id, goal, goal_hash, step_index, context_snapshot, "
                "completed_steps, total_steps, created_at, expires_at "
                "FROM chain_checkpoints WHERE chain_id = ?",
                (chain_id,),
            ).fetchone()
        if not row:
            return None

        checkpoint = ChainCheckpoint(
            chain_id=row[0],
            goal=row[1],
            goal_hash=row[2],
            step_index=int(row[3]),
            context_snapshot=json.loads(row[4]),
            completed_steps=json.loads(row[5]),
            total_steps=int(row[6]),
            created_at=float(row[7]),
            expires_at=float(row[8]),
        )

        if checkpoint.is_expired:
            self.delete(chain_id)
            return None

        if current_goal is not None:
            expected = goal_hash(current_goal)
            if expected != checkpoint.goal_hash:
                raise CheckpointGoalMismatch(
                    f"checkpoint goal_hash {checkpoint.goal_hash[:12]} "
                    f"!= current goal hash {expected[:12]} for chain {chain_id}"
                )

        return checkpoint

    def delete(self, chain_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM chain_checkpoints WHERE chain_id = ?", (chain_id,))
            return cur.rowcount > 0

    def list(self, include_expired: bool = False) -> List[ChainCheckpoint]:
        now = time.time()
        with self._lock:
            if include_expired:
                rows = self._conn.execute(
                    "SELECT chain_id, goal, goal_hash, step_index, context_snapshot, "
                    "completed_steps, total_steps, created_at, expires_at "
                    "FROM chain_checkpoints ORDER BY created_at DESC"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT chain_id, goal, goal_hash, step_index, context_snapshot, "
                    "completed_steps, total_steps, created_at, expires_at "
                    "FROM chain_checkpoints WHERE expires_at > ? ORDER BY created_at DESC",
                    (now,),
                ).fetchall()

        return [
            ChainCheckpoint(
                chain_id=r[0],
                goal=r[1],
                goal_hash=r[2],
                step_index=int(r[3]),
                context_snapshot=json.loads(r[4]),
                completed_steps=json.loads(r[5]),
                total_steps=int(r[6]),
                created_at=float(r[7]),
                expires_at=float(r[8]),
            )
            for r in rows
        ]

    def purge_expired(self) -> int:
        now = time.time()
        with self._lock:
            cur = self._conn.execute("DELETE FROM chain_checkpoints WHERE expires_at <= ?", (now,))
            return cur.rowcount
