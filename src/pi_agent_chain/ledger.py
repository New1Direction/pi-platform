"""Immutable state ledger for deterministic replay."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from pi_agent_chain.models import ExecutionTrace


class StateLedger:
    """SQLite-backed append-only execution trace ledger."""

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self.db_path = db_path
        self._memory_conn: sqlite3.Connection | None = None
        self._ensure_schema()

    @contextmanager
    def _conn(self) -> Generator[sqlite3.Connection, None, None]:
        if self.db_path == ":memory:":
            if self._memory_conn is None:
                self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
                self._memory_conn.row_factory = sqlite3.Row
            yield self._memory_conn
            self._memory_conn.commit()
            return
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _ensure_schema(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_trace (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    trace_id TEXT NOT NULL,
                    node_name TEXT NOT NULL,
                    input_payload_hash TEXT NOT NULL,
                    llm_seed INTEGER NOT NULL,
                    llm_temperature REAL NOT NULL,
                    raw_output TEXT NOT NULL,
                    is_valid_type INTEGER NOT NULL,
                    is_finding INTEGER NOT NULL DEFAULT 0,
                    timestamp TEXT NOT NULL,
                    error_message TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_trace_id ON execution_trace(trace_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_node_name ON execution_trace(node_name)")

    def append(self, trace: ExecutionTrace) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO execution_trace
                (trace_id, node_name, input_payload_hash, llm_seed,
                 llm_temperature, raw_output, is_valid_type, is_finding, timestamp, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    trace.trace_id,
                    trace.node_name,
                    trace.input_payload_hash,
                    trace.llm_seed,
                    trace.llm_temperature,
                    trace.raw_output,
                    int(trace.is_valid_type),
                    int(trace.is_finding),
                    trace.timestamp.isoformat(),
                    trace.error_message,
                ),
            )

    def get_trace(self, trace_id: str) -> List[ExecutionTrace]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM execution_trace WHERE trace_id = ? ORDER BY id",
                (trace_id,),
            ).fetchall()
            return [self._row_to_trace(row) for row in rows]

    def get_all(self, limit: int = 1000, offset: int = 0) -> List[ExecutionTrace]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM execution_trace ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [self._row_to_trace(row) for row in rows]

    def get_latest_for_node(self, node_name: str, trace_id: str) -> Optional[ExecutionTrace]:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM execution_trace
                WHERE node_name = ? AND trace_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (node_name, trace_id),
            ).fetchone()
            return self._row_to_trace(row) if row else None

    def get_state_packet(self, trace_id: str) -> Dict[str, Any]:
        """Reconstruct the full immutable state packet for a given trace."""
        traces = self.get_trace(trace_id)
        return {
            "trace_id": trace_id,
            "total_steps": len(traces),
            "steps": [
                {
                    "node_name": t.node_name,
                    "input_hash": t.input_payload_hash,
                    "output": t.raw_output,
                    "seed": t.llm_seed,
                    "temperature": t.llm_temperature,
                    "valid": t.is_valid_type,
                    "error": t.error_message,
                    "timestamp": t.timestamp.isoformat(),
                }
                for t in traces
            ],
        }

    def compute_state_hash(self, trace_id: str) -> str:
        """Content-addressed deterministic state hash.

        The hash is a pure function of the LOGICAL execution content (node
        names, input hashes, outputs, seeds, etc.) plus causal/structural
        ordering. The following are recorded as metadata in
        :meth:`get_state_packet` but are intentionally EXCLUDED from the
        hashed input so that the same logical trace reproduces the same state
        hash across runs:

        - per-row wall-clock ``timestamp`` values (volatile clock), and
        - the ``trace_id`` itself, which is a random ``uuid4`` correlation id
          (a non-logical identifier; folding it in salts every run).
        """
        packet = self.get_state_packet(trace_id)
        canonical_packet = {
            "total_steps": packet["total_steps"],
            "steps": [
                {k: v for k, v in step.items() if k != "timestamp"}
                for step in packet["steps"]
            ],
        }
        canonical = json.dumps(canonical_packet, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    @staticmethod
    def _row_to_trace(row: sqlite3.Row) -> ExecutionTrace:
        return ExecutionTrace(
            trace_id=row["trace_id"],
            node_name=row["node_name"],
            input_payload_hash=row["input_payload_hash"],
            llm_seed=row["llm_seed"],
            llm_temperature=row["llm_temperature"],
            raw_output=row["raw_output"],
            is_valid_type=bool(row["is_valid_type"]),
            is_finding=bool(row["is_finding"]) if "is_finding" in row.keys() else False,
            timestamp=datetime.fromisoformat(row["timestamp"]),
            error_message=row["error_message"],
        )
