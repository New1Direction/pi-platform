"""
memory.py — PiChainMemory: persistent cross-chain knowledge store.

SQLite FTS5-backed memory shared across chain executions. Bounded growth:
when row count exceeds PI_MEMORY_MAX_ROWS the oldest entries are pruned and
VACUUM is run periodically to reclaim space.

Storage:
  - Default: file at PI_MEMORY_PATH env var, or ~/.pi_platform/memory.db
  - Tests: pass db_path=":memory:" for in-process isolation
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_DEFAULT_MAX_ROWS = int(os.environ.get("PI_MEMORY_MAX_ROWS", "10000"))
_DEFAULT_VACUUM_EVERY = int(os.environ.get("PI_MEMORY_VACUUM_EVERY", "500"))


def _default_db_path() -> str:
    env = os.environ.get("PI_MEMORY_PATH", "").strip()
    if env:
        return env
    home = Path.home()
    pi_dir = home / ".pi_platform"
    pi_dir.mkdir(exist_ok=True)
    return str(pi_dir / "memory.db")


class MemoryEntry(BaseModel):
    entry_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    key: str
    body: str
    chain_id: Optional[str] = None
    agent_name: Optional[str] = None
    risk_score: float = 0.0
    created_at: float = Field(default_factory=time.time)
    body_hash: str = ""

    def fingerprint(self) -> str:
        h = hashlib.sha256()
        h.update(self.key.encode("utf-8"))
        h.update(b"\x00")
        h.update(self.body.encode("utf-8"))
        return h.hexdigest()


class PiChainMemory:
    """
    Bounded FTS5-backed memory store.

    - remember(key, body, ...): insert a fact, prune oldest if over cap
    - recall(query, top_k): FTS5 ranked search
    - export_chain_context(chain_id): pull every memory tied to one chain
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        max_rows: int = _DEFAULT_MAX_ROWS,
        vacuum_every: int = _DEFAULT_VACUUM_EVERY,
    ):
        self.db_path = db_path or _default_db_path()
        self.max_rows = max(1, int(max_rows))
        self.vacuum_every = max(1, int(vacuum_every))
        self._lock = threading.RLock()
        self._writes_since_vacuum = 0
        self._conn = sqlite3.connect(
            self.db_path,
            timeout=30.0,
            isolation_level=None,
            check_same_thread=False,
        )
        if self.db_path != ":memory:":
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError:
                pass
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        return self._conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._conn
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS memory_entries (
                    entry_id TEXT PRIMARY KEY,
                    key TEXT NOT NULL,
                    body TEXT NOT NULL,
                    chain_id TEXT,
                    agent_name TEXT,
                    risk_score REAL DEFAULT 0,
                    created_at REAL NOT NULL,
                    body_hash TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_memory_chain ON memory_entries(chain_id);
                CREATE INDEX IF NOT EXISTS idx_memory_created ON memory_entries(created_at);
                CREATE INDEX IF NOT EXISTS idx_memory_hash ON memory_entries(body_hash);
                """
            )
            try:
                conn.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts "
                    "USING fts5(entry_id UNINDEXED, key, body, agent_name)"
                )
            except sqlite3.OperationalError:
                pass

    def remember(
        self,
        key: str,
        body: str,
        chain_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        risk_score: float = 0.0,
    ) -> MemoryEntry:
        entry = MemoryEntry(
            key=key,
            body=body,
            chain_id=chain_id,
            agent_name=agent_name,
            risk_score=float(risk_score),
        )
        entry.body_hash = entry.fingerprint()

        with self._lock:
            conn = self._conn
            conn.execute(
                "INSERT OR REPLACE INTO memory_entries "
                "(entry_id, key, body, chain_id, agent_name, risk_score, created_at, body_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entry.entry_id,
                    entry.key,
                    entry.body,
                    entry.chain_id,
                    entry.agent_name,
                    entry.risk_score,
                    entry.created_at,
                    entry.body_hash,
                ),
            )
            try:
                conn.execute(
                    "INSERT INTO memory_fts (entry_id, key, body, agent_name) VALUES (?, ?, ?, ?)",
                    (entry.entry_id, entry.key, entry.body, entry.agent_name or ""),
                )
            except sqlite3.OperationalError:
                pass

            self._enforce_size_cap(conn)
            self._writes_since_vacuum += 1
            if self._writes_since_vacuum >= self.vacuum_every:
                try:
                    conn.execute("VACUUM")
                except sqlite3.OperationalError:
                    pass
                self._writes_since_vacuum = 0

        return entry

    def _enforce_size_cap(self, conn: sqlite3.Connection) -> None:
        row = conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()
        if not row:
            return
        total = int(row[0])
        if total <= self.max_rows:
            return
        excess = total - self.max_rows
        to_delete = [
            r[0]
            for r in conn.execute(
                "SELECT entry_id FROM memory_entries ORDER BY created_at ASC LIMIT ?",
                (excess,),
            ).fetchall()
        ]
        if not to_delete:
            return
        placeholders = ",".join("?" for _ in to_delete)
        conn.execute(f"DELETE FROM memory_entries WHERE entry_id IN ({placeholders})", to_delete)
        try:
            conn.execute(f"DELETE FROM memory_fts WHERE entry_id IN ({placeholders})", to_delete)
        except sqlite3.OperationalError:
            pass

    def recall(self, query: str, top_k: int = 5) -> List[MemoryEntry]:
        if not query.strip():
            return []
        rows: List[tuple] = []
        with self._lock:
            conn = self._conn
            try:
                rows = conn.execute(
                    "SELECT m.entry_id, m.key, m.body, m.chain_id, m.agent_name, "
                    "m.risk_score, m.created_at, m.body_hash "
                    "FROM memory_fts f JOIN memory_entries m ON f.entry_id = m.entry_id "
                    "WHERE memory_fts MATCH ? ORDER BY rank LIMIT ?",
                    (query, int(top_k)),
                ).fetchall()
            except sqlite3.OperationalError:
                like = f"%{query}%"
                rows = conn.execute(
                    "SELECT entry_id, key, body, chain_id, agent_name, risk_score, created_at, body_hash "
                    "FROM memory_entries WHERE key LIKE ? OR body LIKE ? "
                    "ORDER BY created_at DESC LIMIT ?",
                    (like, like, int(top_k)),
                ).fetchall()

        out: List[MemoryEntry] = []
        for r in rows:
            out.append(
                MemoryEntry(
                    entry_id=r[0],
                    key=r[1],
                    body=r[2],
                    chain_id=r[3],
                    agent_name=r[4],
                    risk_score=float(r[5] or 0.0),
                    created_at=float(r[6]),
                    body_hash=r[7] or "",
                )
            )
        return out

    def export_chain_context(self, chain_id: str) -> Dict[str, Any]:
        if not chain_id:
            return {"chain_id": "", "entries": []}
        with self._lock:
            conn = self._conn
            rows = conn.execute(
                "SELECT entry_id, key, body, agent_name, risk_score, created_at "
                "FROM memory_entries WHERE chain_id = ? ORDER BY created_at ASC",
                (chain_id,),
            ).fetchall()
        entries = [
            {
                "entry_id": r[0],
                "key": r[1],
                "body_preview": (r[2] or "")[:500],
                "agent_name": r[3],
                "risk_score": float(r[4] or 0.0),
                "created_at": float(r[5]),
            }
            for r in rows
        ]
        return {"chain_id": chain_id, "entries": entries, "count": len(entries)}

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            conn = self._conn
            total = conn.execute("SELECT COUNT(*) FROM memory_entries").fetchone()[0]
            oldest = conn.execute("SELECT MIN(created_at) FROM memory_entries").fetchone()[0]
        return {
            "total_rows": int(total or 0),
            "max_rows": self.max_rows,
            "oldest_created_at": float(oldest) if oldest else None,
            "db_path": self.db_path,
        }

    def purge(self) -> None:
        with self._lock:
            conn = self._conn
            conn.execute("DELETE FROM memory_entries")
            try:
                conn.execute("DELETE FROM memory_fts")
            except sqlite3.OperationalError:
                pass
            try:
                conn.execute("VACUUM")
            except sqlite3.OperationalError:
                pass
