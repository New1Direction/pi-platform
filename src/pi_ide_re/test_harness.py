"""
test_harness.py - per-target isolation + capture DB + snapshots (Theme 1, P3).

Modeled on KikkaSkills/analysis/agmsg/re-analysis/agmsg_test_utils.py (load/reset
env, capture-DB query, state snapshot), adapted to the pi_ide_re campaign tree.

* ``CaptureDB`` - a content-addressed SQLite store for captured observations
  (messages/strings/requests). ``record()`` is idempotent (dedup by content
  hash); ``query()`` is deterministically ordered.
* ``CampaignWorkspace`` - an isolated ``re/<target>/`` working tree with the
  standard subdirs, a ``reset()`` that wipes only this target, and a
  deterministic ``snapshot()`` for forensics/diffing.
"""

from __future__ import annotations

import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from .graph_schema import content_hash

_SUBDIRS = ["payloads", "phases", "threat-model", "ports", "logs"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CaptureDB:
    """Content-addressed SQLite store of captured observations."""

    def __init__(self, db_path: Union[str, Path] = ":memory:"):
        self.db_path = str(db_path)
        self._conn = sqlite3.connect(self.db_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS captures (
                hash TEXT PRIMARY KEY,
                phase TEXT, agent TEXT, kind TEXT,
                key TEXT, value TEXT, captured_at TEXT
            )
            """
        )
        self._conn.commit()

    def record(
        self,
        *,
        phase: str,
        agent: str,
        kind: str,
        key: str,
        value: str,
        captured_at: Optional[str] = None,
    ) -> str:
        """Idempotently record an observation; returns its content hash."""
        h = content_hash({"phase": phase, "agent": agent, "kind": kind, "key": key, "value": value})
        self._conn.execute(
            "INSERT OR IGNORE INTO captures (hash, phase, agent, kind, key, value, captured_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (h, phase, agent, kind, key, value, captured_at or _now_iso()),
        )
        self._conn.commit()
        return h

    def query(
        self, phase: Optional[str] = None, agent: Optional[str] = None, kind: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        clauses, params = [], []
        for col, val in (("phase", phase), ("agent", agent), ("kind", kind)):
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM captures{where} ORDER BY phase, agent, key, hash"
        return [dict(r) for r in self._conn.execute(sql, params).fetchall()]

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0])

    def reset(self) -> None:
        self._conn.execute("DELETE FROM captures")
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()


class CampaignWorkspace:
    """An isolated re/<target>/ working tree."""

    def __init__(self, root: Union[str, Path], target: str, db_path: Optional[Union[str, Path]] = None):
        self.root = Path(root).expanduser().resolve()
        self.target = target
        self.target_dir = self.root / target
        self.db = CaptureDB(db_path if db_path is not None else ":memory:")

    def ensure(self) -> "CampaignWorkspace":
        for sub in _SUBDIRS:
            (self.target_dir / sub).mkdir(parents=True, exist_ok=True)
        return self

    def reset(self) -> None:
        """Wipe ONLY this target's tree (siblings under root untouched)."""
        if self.target_dir.exists():
            shutil.rmtree(self.target_dir)
        self.db.reset()

    def snapshot(self) -> Dict[str, Any]:
        """Deterministic forensic snapshot: sorted relative file list + capture count."""
        files: List[str] = []
        if self.target_dir.exists():
            files = sorted(
                str(p.relative_to(self.target_dir).as_posix()) for p in self.target_dir.rglob("*") if p.is_file()
            )
        return {"target": self.target, "files": files, "captures": self.db.count()}
