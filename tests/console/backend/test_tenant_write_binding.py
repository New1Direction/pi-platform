"""The JWT middleware binds the AUTHENTICATED tenant into tenant_context.

This is the wiring that makes write-path stamping real: while serving an
authenticated request, current_tenant() reflects the caller's JWT tenant_id
claim, so any ExecutionTrace written downstream is attributed correctly. The
attribution source is the JWT claim, NOT the client-supplied X-Tenant-ID header
(which a caller could forge). Uses a sync probe route to exercise the
threadpool context-propagation path that real sync handlers take.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from pi_agent_chain.tenant_context import current_tenant
from pi_console import main as console_main
from pi_production.security.auth import JWTToken

_SECRET = "tenant-write-binding-secret"


def _app_with_probe(monkeypatch):
    monkeypatch.setattr(console_main, "JWT_SECRET", _SECRET)
    monkeypatch.delenv("PI_CONSOLE_ALLOW_UNAUTHENTICATED", raising=False)
    app = console_main.create_app()

    @app.get("/api/v1/_probe_tenant")
    def _probe():  # sync -> runs in the threadpool, exercising context propagation
        return {"tenant": current_tenant()}

    return app


def _tok(**claims) -> str:
    return JWTToken(_SECRET).encode(claims)


def test_authenticated_tenant_is_bound(monkeypatch):
    client = TestClient(_app_with_probe(monkeypatch))
    tok = _tok(sub="u", tenant_id="tenant-a", role="user")
    r = client.get("/api/v1/_probe_tenant", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    assert r.json()["tenant"] == "tenant-a"


def test_header_cannot_forge_tenant(monkeypatch):
    client = TestClient(_app_with_probe(monkeypatch))
    tok = _tok(sub="u", tenant_id="tenant-a", role="user")
    r = client.get(
        "/api/v1/_probe_tenant",
        headers={"Authorization": f"Bearer {tok}", "X-Tenant-ID": "tenant-evil"},
    )
    assert r.json()["tenant"] == "tenant-a"  # the JWT claim wins, not the header


def test_no_tenant_claim_defaults(monkeypatch):
    client = TestClient(_app_with_probe(monkeypatch))
    tok = _tok(sub="u", role="user")  # no tenant_id claim
    r = client.get("/api/v1/_probe_tenant", headers={"Authorization": f"Bearer {tok}"})
    assert r.json()["tenant"] == "default"


def test_request_does_not_leak_tenant_across_calls(monkeypatch):
    client = TestClient(_app_with_probe(monkeypatch))
    client.get("/api/v1/_probe_tenant", headers={"Authorization": f"Bearer {_tok(tenant_id='tenant-a')}"})
    # a fresh request with no tenant claim must not inherit tenant-a
    r = client.get("/api/v1/_probe_tenant", headers={"Authorization": f"Bearer {_tok(sub='u')}"})
    assert r.json()["tenant"] == "default"
