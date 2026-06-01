"""Fail-closed authentication gate for the sensitive console read surfaces.

Critical finding: the ledger + transparency endpoints served every tenant's
execution audit data with NO authentication by default (JWT was opt-in and the
shipped config left it off). These tests pin the fail-closed contract:

  * default (no JWT configured)            -> 401 (refuse, do not serve data)
  * JWT configured + valid bearer token    -> reachable
  * explicit local-dev opt-out env var      -> reachable without a token
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pi_console import main as console_main
from pi_console.routers import ledger_router
from pi_production.security.auth import JWTToken

_OPTOUT = "PI_CONSOLE_ALLOW_UNAUTHENTICATED"


@pytest.fixture(autouse=True)
def _isolate_db(monkeypatch, tmp_path):
    # Point the ledger at a non-existent DB so authorized reads return an empty
    # summary (200) instead of touching the repo's real ledger file.
    monkeypatch.setattr(ledger_router, "DB_PATH", str(tmp_path / "no_such_ledger.db"))


def _app(monkeypatch, *, jwt_secret, optout=False):
    monkeypatch.setattr(console_main, "JWT_SECRET", jwt_secret)
    if optout:
        monkeypatch.setenv(_OPTOUT, "1")
    else:
        monkeypatch.delenv(_OPTOUT, raising=False)
    return TestClient(console_main.create_app())


def test_ledger_requires_auth_by_default(monkeypatch):
    client = _app(monkeypatch, jwt_secret=None)
    r = client.get("/api/v1/ledger/summary")
    assert r.status_code == 401


def test_transparency_requires_auth_by_default(monkeypatch):
    client = _app(monkeypatch, jwt_secret=None)
    r = client.get("/api/v1/transparency/scheduler/stats")
    assert r.status_code == 401


def test_ledger_trace_detail_requires_auth_by_default(monkeypatch):
    client = _app(monkeypatch, jwt_secret=None)
    r = client.get("/api/v1/ledger/trace/anything")
    assert r.status_code == 401


def test_valid_token_grants_access(monkeypatch):
    client = _app(monkeypatch, jwt_secret="test-secret-abc")
    token = JWTToken("test-secret-abc").encode({"sub": "u1", "tenant_id": "t1", "role": "admin"})
    r = client.get("/api/v1/ledger/summary", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200


def test_dev_optout_allows_unauthenticated(monkeypatch):
    client = _app(monkeypatch, jwt_secret=None, optout=True)
    r = client.get("/api/v1/ledger/summary")
    assert r.status_code != 401
