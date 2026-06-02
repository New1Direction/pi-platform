"""The async/thread-local current-tenant used to stamp execution-trace writes.

Read-side isolation already existed; this carries the *authenticated* tenant
from the request boundary down to wherever a trace is written, so audit rows
stop defaulting to 'default'. The tenant source is the JWT claim (trusted), not
the client X-Tenant-ID header (forgeable).
"""

from __future__ import annotations

from pi_agent_chain.tenant_context import (
    DEFAULT_TENANT,
    current_tenant,
    set_tenant,
    tenant_from_claims,
    tenant_scope,
)


class TestContextVar:
    def test_default_is_default_tenant(self):
        assert current_tenant() == DEFAULT_TENANT

    def test_scope_sets_and_restores(self):
        assert current_tenant() == DEFAULT_TENANT
        with tenant_scope("acme"):
            assert current_tenant() == "acme"
        assert current_tenant() == DEFAULT_TENANT  # restored on exit

    def test_scope_restores_on_exception(self):
        try:
            with tenant_scope("acme"):
                raise ValueError("boom")
        except ValueError:
            pass
        assert current_tenant() == DEFAULT_TENANT

    def test_nested_scopes(self):
        with tenant_scope("a"):
            with tenant_scope("b"):
                assert current_tenant() == "b"
            assert current_tenant() == "a"

    def test_set_tenant_token_resets(self):
        tok = set_tenant("x")
        assert current_tenant() == "x"
        from pi_agent_chain.tenant_context import reset_tenant

        reset_tenant(tok)
        assert current_tenant() == DEFAULT_TENANT

    def test_invalid_tenant_falls_back_to_default(self):
        with tenant_scope("bad/../slash"):
            assert current_tenant() == DEFAULT_TENANT
        with tenant_scope(""):
            assert current_tenant() == DEFAULT_TENANT


class TestTenantFromClaims:
    def test_extracts_claim(self):
        assert tenant_from_claims({"tenant_id": "acme", "sub": "u"}) == "acme"

    def test_none_or_missing_is_default(self):
        assert tenant_from_claims(None) == DEFAULT_TENANT
        assert tenant_from_claims({"sub": "u"}) == DEFAULT_TENANT

    def test_forged_invalid_claim_is_default(self):
        # a malformed tenant claim must never become a real attribution
        assert tenant_from_claims({"tenant_id": "../etc"}) == DEFAULT_TENANT
