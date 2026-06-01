"""Deterministic Append-Only Persistent Storage.

SQLite with WAL mode for concurrent reads, file locking for safe writes.
Every row is append-only (UPDATE forbidden, DELETE forbidden).
Hash chaining for cryptographic integrity verification.
Tenant isolation enforced at schema + query level.

No ORM — raw SQL for deterministic schema control.
No probabilistic anything. All writes are deterministic, receipt-linked.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple


class StorageError(Exception):
    """Base storage error — always deterministic and safe to serialize."""


class HashChainBreakError(StorageError):
    """Raised when cryptographic integrity verification fails."""


class TenantIsolationError(StorageError):
    """Raised when tenant boundary is violated."""


class MutationForbiddenError(StorageError):
    """Raised when an UPDATE or DELETE is attempted on an append-only table."""


# ──────────────────────────────
#  Schema Definition
# ──────────────────────────────

PRODUCTION_SCHEMA = """
-- ================================================================
-- PI Platform Production Storage Schema
-- Append-only, hash-chained, tenant-partitioned
-- Version: 1.2-prod
-- ================================================================

PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;

-- Tenant boundaries enforced at DB level
CREATE TABLE IF NOT EXISTS snapshots (
    row_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id       TEXT NOT NULL UNIQUE,
    tenant_id         TEXT NOT NULL,
    source_id         TEXT NOT NULL,
    snapshot_type     TEXT NOT NULL,
    created_at        TEXT NOT NULL,  -- canonical_timestamp
    sequence_number   INTEGER NOT NULL,
    payload_hash      TEXT NOT NULL,
    payload_json      TEXT NOT NULL,
    previous_hash     TEXT NOT NULL,
    artifact_hash     TEXT NOT NULL,
    -- Compound indexes for tenant-scoped fast queries
    UNIQUE(tenant_id, snapshot_id)
);

CREATE INDEX IF NOT EXISTS idx_snapshots_tenant ON snapshots(tenant_id);
CREATE INDEX IF NOT EXISTS idx_snapshots_tenant_source_type ON snapshots(tenant_id, source_id, snapshot_type);
CREATE INDEX IF NOT EXISTS idx_snapshots_created ON snapshots(created_at);

-- Audit log: every API and console action
CREATE TABLE IF NOT EXISTS audit_log (
    row_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id          TEXT NOT NULL UNIQUE,
    tenant_id         TEXT NOT NULL,
    actor_id          TEXT NOT NULL,
    actor_type        TEXT NOT NULL,  -- CONSOLE, API, WORKER, SYSTEM
    action            TEXT NOT NULL,
    resource_type     TEXT NOT NULL,
    resource_id       TEXT NOT NULL,
    request_payload   TEXT NOT NULL DEFAULT '{}',
    response_summary  TEXT NOT NULL DEFAULT '{}',
    timestamp         TEXT NOT NULL,
    correlation_id    TEXT NOT NULL,
    session_id        TEXT,
    risk_assessment   TEXT NOT NULL DEFAULT '{}',
    -- Hash chain for tamper evidence
    previous_audit_hash TEXT NOT NULL,
    audit_hash        TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit_log(correlation_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

-- Orchestration receipts (persistent)
CREATE TABLE IF NOT EXISTS receipts (
    row_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    receipt_id        TEXT NOT NULL UNIQUE,
    tenant_id         TEXT NOT NULL,
    worker_id         TEXT NOT NULL,
    phase             TEXT NOT NULL,
    status            TEXT NOT NULL,
    intent_hash       TEXT NOT NULL,
    determinism_proof TEXT NOT NULL,
    output_slot_ids   TEXT NOT NULL DEFAULT '[]',  -- JSON array
    provenance_hash   TEXT NOT NULL,
    timestamp         TEXT NOT NULL,
    metadata_json     TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_receipts_tenant ON receipts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_receipts_worker ON receipts(worker_id);

-- Tenant registry (immutable config)
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id         TEXT PRIMARY KEY,
    tenant_name       TEXT NOT NULL,
    created_at        TEXT NOT NULL,
    policy_json       TEXT NOT NULL DEFAULT '{}',
    quota_json        TEXT NOT NULL DEFAULT '{}',
    active            INTEGER NOT NULL DEFAULT 1,  -- soft disable only
    metadata_json     TEXT NOT NULL DEFAULT '{}'
);

-- Rate-limit tracking (sliding window)
CREATE TABLE IF NOT EXISTS rate_windows (
    window_id         TEXT PRIMARY KEY,
    tenant_id         TEXT NOT NULL,
    actor_id          TEXT NOT NULL,
    window_start      TEXT NOT NULL,
    request_count     INTEGER NOT NULL DEFAULT 0,
    rejected_count    INTEGER NOT NULL DEFAULT 0,
    UNIQUE(tenant_id, actor_id, window_start)
);

CREATE INDEX IF NOT EXISTS idx_rate_windows ON rate_windows(tenant_id, window_start);

-- Health / heartbeat
CREATE TABLE IF NOT EXISTS health_records (
    record_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    component         TEXT NOT NULL,
    status            TEXT NOT NULL,  -- HEALTHY, DEGRADED, FAILED
    message           TEXT,
    recorded_at       TEXT NOT NULL
);
"""


# ──────────────────────────────
#  Connection Pool
# ──────────────────────────────


class ConnectionPool:
    """Thread-safe SQLite connection pool with deterministic settings."""

    def __init__(self, db_path: str, max_connections: int = 10) -> None:
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._max = max_connections
        self._pool: List[sqlite3.Connection] = []
        self._lock = threading.Lock()
        self._local = threading.local()
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.executescript(PRODUCTION_SCHEMA)
        conn.commit()
        conn.close()

    @contextmanager
    def get(self) -> Iterator[sqlite3.Connection]:
        if hasattr(self._local, "conn") and self._local.conn:
            yield self._local.conn
            return
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        self._local.conn = conn
        try:
            yield conn
        finally:
            conn.close()
            self._local.conn = None

    def execute_write(self, sql: str, params: Tuple[Any, ...] = ()) -> int:
        """Append-only write. Returns lastrowid."""
        with self._lock:
            with self.get() as conn:
                cur = conn.execute(sql, params)
                conn.commit()
                return cur.lastrowid or 0

    def execute_read(self, sql: str, params: Tuple[Any, ...] = ()) -> List[sqlite3.Row]:
        with self.get() as conn:
            return conn.execute(sql, params).fetchall()


# ──────────────────────────────
#  Append-Only Integrity Trigger Installer
# ──────────────────────────────

INTEGRITY_TRIGGERS = """
-- Prevent UPDATE/DELETE on append-only tables (REPLAYED operations only)
CREATE TRIGGER IF NOT EXISTS prevent_snapshots_update
    BEFORE UPDATE ON snapshots
BEGIN
    SELECT RAISE(ABORT, 'MUTATION_FORBIDDEN: snapshots is append-only');
END;

CREATE TRIGGER IF NOT EXISTS prevent_snapshots_delete
    BEFORE DELETE ON snapshots
BEGIN
    SELECT RAISE(ABORT, 'MUTATION_FORBIDDEN: snapshots is append-only');
END;

CREATE TRIGGER IF NOT EXISTS prevent_audit_update
    BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'MUTATION_FORBIDDEN: audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
    BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'MUTATION_FORBIDDEN: audit_log is append-only');
END;

CREATE TRIGGER IF NOT EXISTS prevent_receipts_update
    BEFORE UPDATE ON receipts
BEGIN
    SELECT RAISE(ABORT, 'MUTATION_FORBIDDEN: receipts is append-only');
END;

CREATE TRIGGER IF NOT EXISTS prevent_receipts_delete
    BEFORE DELETE ON receipts
BEGIN
    SELECT RAISE(ABORT, 'MUTATION_FORBIDDEN: receipts is append-only');
END;
"""


def install_append_only_triggers(pool: ConnectionPool) -> None:
    """Install DB-level mutation guards after schema init."""
    with pool.get() as conn:
        conn.executescript(INTEGRITY_TRIGGERS)
        conn.commit()


# ──────────────────────────────
#  Snapshot Persist
# ──────────────────────────────


class SnapshotPersister:
    """Deterministic, append-only snapshot persistence with hash chaining."""

    def __init__(self, pool: ConnectionPool) -> None:
        self.pool = pool

    def persist(
        self,
        snapshot_id: str,
        tenant_id: str,
        source_id: str,
        snapshot_type: str,
        created_at: str,
        sequence_number: int,
        payload_hash: str,
        payload_json: str,
        previous_hash: str,
    ) -> None:
        artifact_hash = hashlib.sha256(
            f"{snapshot_id}:{tenant_id}:{source_id}:{snapshot_type}:{created_at}:{sequence_number}:{payload_hash}:{previous_hash}".encode()
        ).hexdigest()

        self.pool.execute_write(
            """
            INSERT INTO snapshots (snapshot_id, tenant_id, source_id, snapshot_type,
                created_at, sequence_number, payload_hash, payload_json, previous_hash, artifact_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                tenant_id,
                source_id,
                snapshot_type,
                created_at,
                sequence_number,
                payload_hash,
                payload_json,
                previous_hash,
                artifact_hash,
            ),
        )

    def get_latest(self, tenant_id: str, source_id: str, snapshot_type: str) -> Optional[Dict[str, Any]]:
        rows = self.pool.execute_read(
            """
            SELECT * FROM snapshots
            WHERE tenant_id = ? AND source_id = ? AND snapshot_type = ?
            ORDER BY sequence_number DESC LIMIT 1
            """,
            (tenant_id, source_id, snapshot_type),
        )
        return dict(rows[0]) if rows else None

    def get_chain(self, tenant_id: str, source_id: str, snapshot_type: str) -> List[Dict[str, Any]]:
        rows = self.pool.execute_read(
            """
            SELECT * FROM snapshots
            WHERE tenant_id = ? AND source_id = ? AND snapshot_type = ?
            ORDER BY sequence_number ASC
            """,
            (tenant_id, source_id, snapshot_type),
        )
        return [dict(r) for r in rows]

    def verify_chain(self, tenant_id: str, source_id: str, snapshot_type: str) -> Tuple[bool, List[str]]:
        rows = self.get_chain(tenant_id, source_id, snapshot_type)
        errors: List[str] = []
        prev_hash = ""
        for row in rows:
            computed = hashlib.sha256(
                f"{row['snapshot_id']}:{row['tenant_id']}:{row['source_id']}:{row['snapshot_type']}:{row['created_at']}:{row['sequence_number']}:{row['payload_hash']}:{row['previous_hash']}".encode()
            ).hexdigest()
            if computed != row["artifact_hash"]:
                errors.append(f"hash_mismatch:snapshot_id={row['snapshot_id']}")
            if row["previous_hash"] != prev_hash:
                errors.append(f"chain_break:snapshot_id={row['snapshot_id']}")
            prev_hash = row["artifact_hash"]
        return (len(errors) == 0, errors)


# ──────────────────────────────
#  Audit Logger
# ──────────────────────────────


class AuditLogger:
    """Append-only audit logger with hash chaining and correlation IDs."""

    def __init__(self, pool: ConnectionPool) -> None:
        self.pool = pool
        self._lock = threading.Lock()
        self._last_audit_hash: Dict[str, str] = {}

    def log(
        self,
        tenant_id: str,
        actor_id: str,
        actor_type: str,  # CONSOLE | API | WORKER | SYSTEM
        action: str,
        resource_type: str,
        resource_id: str,
        request_payload: Dict[str, Any],
        response_summary: Dict[str, Any],
        correlation_id: str,
        session_id: Optional[str] = None,
        risk_assessment: Optional[Dict[str, Any]] = None,
    ) -> str:
        audit_id = f"audit_{tenant_id}_{actor_id}_{int(time.time() * 1_000_000)}"
        timestamp = datetime.now(timezone.utc).isoformat()
        prev_hash = self._last_audit_hash.get(tenant_id, "")

        # The chained audit_hash must be reproducible: it covers only the LOGICAL
        # event + the chain link (prev_hash), NOT the wall-clock audit_id or
        # timestamp. Those are still STORED as columns (for humans / uniqueness),
        # but folding them in made replaying the same logical sequence produce a
        # different chain, breaking the "immutable, replayable audit ledger" claim.
        payload = json.dumps(
            {
                "tenant_id": tenant_id,
                "actor_id": actor_id,
                "actor_type": actor_type,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "correlation_id": correlation_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        audit_hash = hashlib.sha256(f"{prev_hash}:{payload}".encode()).hexdigest()

        self.pool.execute_write(
            """
            INSERT INTO audit_log (audit_id, tenant_id, actor_id, actor_type, action,
                resource_type, resource_id, request_payload, response_summary, timestamp,
                correlation_id, session_id, risk_assessment, previous_audit_hash, audit_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                tenant_id,
                actor_id,
                actor_type,
                action,
                resource_type,
                resource_id,
                json.dumps(request_payload, sort_keys=True),
                json.dumps(response_summary, sort_keys=True),
                timestamp,
                correlation_id,
                session_id or "",
                json.dumps(risk_assessment or {}, sort_keys=True),
                prev_hash,
                audit_hash,
            ),
        )

        self._last_audit_hash[tenant_id] = audit_hash
        return audit_id

    def query(self, tenant_id: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        rows = self.pool.execute_read(
            "SELECT * FROM audit_log WHERE tenant_id = ? ORDER BY row_id DESC LIMIT ? OFFSET ?",
            (tenant_id, limit, offset),
        )
        return [dict(r) for r in rows]


# ──────────────────────────────
#  Receipt Persister
# ──────────────────────────────


class ReceiptPersister:
    """Deterministic receipt persistence for provenance chains."""

    def __init__(self, pool: ConnectionPool) -> None:
        self.pool = pool

    def persist(
        self,
        receipt_id: str,
        tenant_id: str,
        worker_id: str,
        phase: str,
        status: str,
        intent_hash: str,
        determinism_proof: str,
        output_slot_ids: List[str],
        provenance_hash: str,
        timestamp: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.pool.execute_write(
            """
            INSERT INTO receipts (receipt_id, tenant_id, worker_id, phase, status,
                intent_hash, determinism_proof, output_slot_ids, provenance_hash,
                timestamp, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt_id,
                tenant_id,
                worker_id,
                phase,
                status,
                intent_hash,
                determinism_proof,
                json.dumps(output_slot_ids, sort_keys=True),
                provenance_hash,
                timestamp,
                json.dumps(metadata or {}, sort_keys=True),
            ),
        )

    def get_by_tenant(self, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        rows = self.pool.execute_read(
            "SELECT * FROM receipts WHERE tenant_id = ? ORDER BY row_id DESC LIMIT ?",
            (tenant_id, limit),
        )
        return [dict(r) for r in rows]


# ──────────────────────────────
#  Rate Limiter (Sliding Window)
# ──────────────────────────────


class RateLimiter:
    """Deterministic sliding-window rate limiter per tenant + actor."""

    def __init__(self, pool: ConnectionPool, default_max: int = 1000, window_seconds: int = 60) -> None:
        self.pool = pool
        self.default_max = default_max
        self.window_seconds = window_seconds

    def _window_key(self, tenant_id: str, actor_id: str, now: int) -> Tuple[str, str]:
        window_start = (now // self.window_seconds) * self.window_seconds
        return (f"{tenant_id}:{actor_id}:{window_start}", str(window_start))

    def check(self, tenant_id: str, actor_id: str) -> Tuple[bool, Dict[str, Any]]:
        now = int(time.time())
        key, window_start = self._window_key(tenant_id, actor_id, now)
        self.pool.execute_write(
            """
            INSERT INTO rate_windows (window_id, tenant_id, actor_id, window_start, request_count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(window_id) DO UPDATE SET request_count = request_count + 1
            """,
            (key, tenant_id, actor_id, window_start),
        )
        rows = self.pool.execute_read(
            "SELECT request_count FROM rate_windows WHERE window_id = ?",
            (key,),
        )
        count = rows[0]["request_count"] if rows else 0
        allowed = count <= self.default_max
        if not allowed:
            self.pool.execute_write(
                "UPDATE rate_windows SET rejected_count = rejected_count + 1 WHERE window_id = ?",
                (key,),
            )
        return (
            allowed,
            {
                "window_id": key,
                "count": count,
                "limit": self.default_max,
                "remaining": max(0, self.default_max - count),
            },
        )

    def get_stats(self, tenant_id: str) -> List[Dict[str, Any]]:
        rows = self.pool.execute_read(
            """
            SELECT * FROM rate_windows
            WHERE tenant_id = ?
            ORDER BY window_start DESC LIMIT 100
            """,
            (tenant_id,),
        )
        return [dict(r) for r in rows]


# ──────────────────────────────
#  Tenant Registry
# ──────────────────────────────


class TenantRegistry:
    """Immutable tenant configuration with soft-disable support."""

    def __init__(self, pool: ConnectionPool) -> None:
        self.pool = pool

    def register(self, tenant_id: str, tenant_name: str, policy: Dict[str, Any], quota: Dict[str, Any]) -> None:
        self.pool.execute_write(
            """
            INSERT INTO tenants (tenant_id, tenant_name, created_at, policy_json, quota_json)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(tenant_id) DO NOTHING
            """,
            (
                tenant_id,
                tenant_name,
                datetime.now(timezone.utc).isoformat(),
                json.dumps(policy, sort_keys=True),
                json.dumps(quota, sort_keys=True),
            ),
        )

    def get(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        rows = self.pool.execute_read("SELECT * FROM tenants WHERE tenant_id = ?", (tenant_id,))
        return dict(rows[0]) if rows else None

    def is_active(self, tenant_id: str) -> bool:
        tenant = self.get(tenant_id)
        return tenant is not None and bool(tenant.get("active", 1))


# ──────────────────────────────
#  Health Recorder
# ──────────────────────────────


class HealthRecorder:
    """Structured health records for liveness/readiness probes."""

    def __init__(self, pool: ConnectionPool) -> None:
        self.pool = pool

    def record(self, component: str, status: str, message: str = "") -> None:
        self.pool.execute_write(
            "INSERT INTO health_records (component, status, message, recorded_at) VALUES (?, ?, ?, ?)",
            (component, status, message, datetime.now(timezone.utc).isoformat()),
        )

    def latest(self, component: str) -> Optional[Dict[str, Any]]:
        rows = self.pool.execute_read(
            "SELECT * FROM health_records WHERE component = ? ORDER BY record_id DESC LIMIT 1",
            (component,),
        )
        return dict(rows[0]) if rows else None

    def status_summary(self) -> Dict[str, Any]:
        rows = self.pool.execute_read(
            "SELECT component, status, MAX(recorded_at) as at FROM health_records GROUP BY component"
        )
        components = {r["component"]: {"status": r["status"], "at": r["at"]} for r in rows}
        overall = "HEALTHY" if all(c["status"] == "HEALTHY" for c in components.values()) else "DEGRADED"
        return {"overall": overall, "components": components}
