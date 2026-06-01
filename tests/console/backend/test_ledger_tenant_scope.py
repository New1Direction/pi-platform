"""Per-tenant isolation on the ledger read surface.

Closes the authZ half of the console finding: once authenticated, a caller must
only see their OWN tenant's execution traces (admins may see all). This pins the
READ-side enforcement; populating tenant_id on the orchestrator write-path is a
separate follow-up (the orchestrator is currently tenant-blind).
"""

from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient

from pi_console import main as console_main
from pi_console.routers import ledger_router
from pi_production.security.auth import JWTToken

_SECRET = "tenant-scope-secret"


def _seed_db(path: str) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE execution_trace (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trace_id TEXT NOT NULL, node_name TEXT NOT NULL,
            input_payload_hash TEXT NOT NULL, llm_seed INTEGER NOT NULL,
            llm_temperature REAL NOT NULL, raw_output TEXT NOT NULL,
            is_valid_type INTEGER NOT NULL, is_finding INTEGER NOT NULL DEFAULT 0,
            timestamp TEXT NOT NULL, error_message TEXT,
            tenant_id TEXT NOT NULL DEFAULT 'default'
        )
        """
    )
    rows = [
        ("trace-a1", "tenant-a"),
        ("trace-a2", "tenant-a"),
        ("trace-b1", "tenant-b"),
    ]
    for trace_id, tenant in rows:
        conn.execute(
            "INSERT INTO execution_trace (trace_id, node_name, input_payload_hash, llm_seed, "
            "llm_temperature, raw_output, is_valid_type, is_finding, timestamp, error_message, tenant_id) "
            "VALUES (?, 'n', 'h', 1, 0.0, '{}', 1, 0, '2026-01-01T00:00:00', NULL, ?)",
            (trace_id, tenant),
        )
    conn.commit()
    conn.close()


@pytest.fixture
def client(monkeypatch, tmp_path):
    db = str(tmp_path / "ledger.db")
    _seed_db(db)
    monkeypatch.setattr(ledger_router, "DB_PATH", db)
    monkeypatch.setattr(console_main, "JWT_SECRET", _SECRET)
    monkeypatch.delenv("PI_CONSOLE_ALLOW_UNAUTHENTICATED", raising=False)
    return TestClient(console_main.create_app())


def _token(**claims) -> str:
    return JWTToken(_SECRET).encode(claims)


def _trace_ids(resp) -> set:
    return {t["trace_id"] for t in resp.json()["traces"]}


def test_tenant_sees_only_own_traces(client):
    tok = _token(sub="u", tenant_id="tenant-a", role="user")
    r = client.get("/api/v1/ledger/traces?limit=200", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert _trace_ids(r) == {"trace-a1", "trace-a2"}  # NOT trace-b1


def test_tenant_cannot_read_other_tenants_trace_detail(client):
    tok = _token(sub="u", tenant_id="tenant-a", role="user")
    r = client.get("/api/v1/ledger/trace/trace-b1", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 404  # tenant-a must not be able to read tenant-b's trace


def test_admin_sees_all_tenants(client):
    tok = _token(sub="admin", tenant_id="tenant-a", role="admin")
    r = client.get("/api/v1/ledger/traces?limit=200", headers={"Authorization": f"Bearer {tok}"})
    assert _trace_ids(r) == {"trace-a1", "trace-a2", "trace-b1"}


def test_token_without_tenant_is_forbidden(client):
    tok = _token(sub="u", role="user")  # no tenant_id claim
    r = client.get("/api/v1/ledger/traces?limit=200", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 403
