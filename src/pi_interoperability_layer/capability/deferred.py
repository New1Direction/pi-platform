"""Deferred tool loading for the capability registry.

Tools can be registered by name + description + category without a schema
(deferred), or with a full JSON Schema (eager). Deferred tools are promoted
to loaded once their schema is resolved on first use.

Thread-safe. Persists to SQLite for crash recovery.
Deterministic: no randomness, no auto-learning.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class DeferredTool(BaseModel):
    """A tool registered without a resolved schema.

    Attributes:
        name: Unique canonical tool name.
        description: Short human-readable description.
        category: Logical grouping (e.g. ``"filesystem"``, ``"git"``).
        tool_schema: JSON Schema dict, or ``None`` if not yet loaded.
        is_deferred: ``True`` while the schema has not been provided.
    """

    name: str
    description: str = ""
    category: str = ""
    tool_schema: Optional[Dict[str, Any]] = Field(default=None, alias="schema")
    is_deferred: bool = True

    model_config = {"frozen": False, "populate_by_name": True}


# ---------------------------------------------------------------------------
# SQLite persistence helpers
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS deferred_tools (
    name        TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    category    TEXT NOT NULL DEFAULT '',
    schema_json TEXT,
    is_deferred INTEGER NOT NULL DEFAULT 1,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_deferred_cat ON deferred_tools(category);
CREATE INDEX IF NOT EXISTS idx_deferred_flag ON deferred_tools(is_deferred);
"""


def _default_db_path() -> str:
    """Return the default SQLite path for the deferred tool store."""
    env = os.environ.get("PI_DEFERRED_TOOLS_DB", "").strip()
    if env:
        return env
    pi_dir = Path.home() / ".pi_platform"
    pi_dir.mkdir(exist_ok=True)
    return str(pi_dir / "deferred_tools.db")


# ---------------------------------------------------------------------------
# ToolSchemaStore
# ---------------------------------------------------------------------------


class ToolSchemaStore:
    """Manages deferred vs loaded tools with SQLite persistence.

    Thread-safe (all public methods acquire ``self._lock``).
    Deterministic — no randomness, no probabilistic scoring.

    Usage::

        store = ToolSchemaStore()
        store.register_deferred("Bash", description="Run shell commands", category="shell")
        store.register_eager("Read", description="Read files", category="fs",
                             schema={"type": "object", ...})

        # Later, when schema is resolved:
        store.promote_to_loaded("Bash", {"type": "object", ...})

        # Query
        store.list_deferred()  # ["Bash"]
        store.list_loaded()    # ["Read"]
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
    ) -> None:
        self._db_path = db_path or _default_db_path()
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            self._db_path,
            timeout=30.0,
            isolation_level=None,
            check_same_thread=False,
        )
        if self._db_path != ":memory:":
            try:
                self._conn.execute("PRAGMA journal_mode=WAL")
            except sqlite3.OperationalError:
                pass
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_DDL)

    # ── Registration ────────────────────────────────────────────────────

    def register_deferred(
        self,
        name: str,
        description: str = "",
        category: str = "",
    ) -> DeferredTool:
        """Register a tool without a schema (deferred loading).

        Args:
            name: Unique tool name.
            description: Short description for discovery.
            category: Logical grouping.

        Returns:
            The created :class:`DeferredTool`.

        Raises:
            ValueError: If *name* is empty.
        """
        if not name:
            raise ValueError("Tool name must not be empty")
        now = datetime.now(timezone.utc).isoformat()
        tool = DeferredTool(
            name=name,
            description=description,
            category=category,
            schema=None,
            is_deferred=True,
        )
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO deferred_tools "
                "(name, description, category, schema_json, is_deferred, updated_at) "
                "VALUES (?, ?, ?, NULL, 1, ?)",
                (name, description, category, now),
            )
        return tool

    def register_eager(
        self,
        name: str,
        description: str = "",
        category: str = "",
        schema: Optional[Dict[str, Any]] = None,
    ) -> DeferredTool:
        """Register a tool with its full schema already resolved.

        Args:
            name: Unique tool name.
            description: Short description.
            category: Logical grouping.
            schema: JSON Schema dict.

        Returns:
            The created :class:`DeferredTool`.
        """
        if not name:
            raise ValueError("Tool name must not be empty")
        now = datetime.now(timezone.utc).isoformat()
        schema_json = json.dumps(schema, sort_keys=True) if schema else None
        is_deferred = schema is None
        tool = DeferredTool(
            name=name,
            description=description,
            category=category,
            schema=schema,
            is_deferred=is_deferred,
        )
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO deferred_tools "
                "(name, description, category, schema_json, is_deferred, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (name, description, category, schema_json, int(is_deferred), now),
            )
        return tool

    # ── Schema resolution ───────────────────────────────────────────────

    def fetch_schema(self, name: str) -> Optional[Dict[str, Any]]:
        """Return the JSON Schema for *name*, or ``None`` if not loaded.

        Args:
            name: Tool name (exact match).

        Returns:
            Schema dict if loaded, ``None`` otherwise.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT schema_json FROM deferred_tools WHERE name = ?",
                (name,),
            ).fetchone()
        if row and row[0]:
            return json.loads(row[0])
        return None

    def promote_to_loaded(self, name: str, schema: Dict[str, Any]) -> DeferredTool:
        """Promote a deferred tool to loaded by providing its schema.

        Args:
            name: Tool name (must already be registered).
            schema: JSON Schema dict.

        Returns:
            Updated :class:`DeferredTool`.

        Raises:
            KeyError: If *name* is not registered.
        """
        now = datetime.now(timezone.utc).isoformat()
        schema_json = json.dumps(schema, sort_keys=True)
        with self._lock:
            cur = self._conn.execute(
                "UPDATE deferred_tools SET schema_json = ?, is_deferred = 0, updated_at = ? WHERE name = ?",
                (schema_json, now, name),
            )
            if cur.rowcount == 0:
                raise KeyError(f"Tool {name!r} is not registered")
        return DeferredTool(
            name=name,
            schema=schema,
            is_deferred=False,
            description=self._get_field(name, "description"),
            category=self._get_field(name, "category"),
        )

    # ── Introspection ───────────────────────────────────────────────────

    def list_deferred(self) -> List[str]:
        """Return names of tools whose schema has NOT been loaded."""
        with self._lock:
            rows = self._conn.execute("SELECT name FROM deferred_tools WHERE is_deferred = 1 ORDER BY name").fetchall()
        return [r[0] for r in rows]

    def list_loaded(self) -> List[str]:
        """Return names of tools whose schema HAS been loaded."""
        with self._lock:
            rows = self._conn.execute("SELECT name FROM deferred_tools WHERE is_deferred = 0 ORDER BY name").fetchall()
        return [r[0] for r in rows]

    def is_loaded(self, name: str) -> bool:
        """True if *name* is registered and fully loaded."""
        with self._lock:
            row = self._conn.execute(
                "SELECT is_deferred FROM deferred_tools WHERE name = ?",
                (name,),
            ).fetchone()
        return row is not None and row[0] == 0

    def get_tool(self, name: str) -> Optional[DeferredTool]:
        """Return the :class:`DeferredTool` for *name*, or ``None``."""
        with self._lock:
            row = self._conn.execute(
                "SELECT name, description, category, schema_json, is_deferred FROM deferred_tools WHERE name = ?",
                (name,),
            ).fetchone()
        if row is None:
            return None
        schema = json.loads(row[3]) if row[3] else None
        return DeferredTool(
            name=row[0],
            description=row[1],
            category=row[2],
            schema=schema,
            is_deferred=bool(row[4]),
        )

    def list_all(self) -> List[DeferredTool]:
        """Return all registered tools."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT name, description, category, schema_json, is_deferred FROM deferred_tools ORDER BY name"
            ).fetchall()
        return [
            DeferredTool(
                name=r[0],
                description=r[1],
                category=r[2],
                schema=json.loads(r[3]) if r[3] else None,
                is_deferred=bool(r[4]),
            )
            for r in rows
        ]

    def stats(self) -> Dict[str, Any]:
        """Return store statistics."""
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM deferred_tools").fetchone()[0]
            deferred = self._conn.execute("SELECT COUNT(*) FROM deferred_tools WHERE is_deferred = 1").fetchone()[0]
            loaded = self._conn.execute("SELECT COUNT(*) FROM deferred_tools WHERE is_deferred = 0").fetchone()[0]
        return {
            "total": int(total),
            "deferred": int(deferred),
            "loaded": int(loaded),
            "db_path": self._db_path,
        }

    # ── Internal helpers ────────────────────────────────────────────────

    def _get_field(self, name: str, field: str) -> str:
        """Fetch a single text field from the DB."""
        with self._lock:
            row = self._conn.execute(
                f"SELECT {field} FROM deferred_tools WHERE name = ?",
                (name,),
            ).fetchone()
        return row[0] if row else ""
