"""Async/thread-local current tenant for stamping execution-trace writes.

The console's read surface already isolates traces per tenant
(``ledger_router`` filters by the caller's JWT claim via
``auth_guard.tenant_scope``). But the orchestrator write paths constructed
``ExecutionTrace`` without a ``tenant_id``, so every real audit row defaulted to
``'default'`` and the read filter never isolated real traffic.

This module carries the *authenticated* tenant from the request boundary
(bound in ``jwt_validation_middleware`` from the JWT claim - NOT the forgeable
``X-Tenant-ID`` header) down to wherever a trace is written. CLI / direct /
background execution falls back to ``DEFAULT_TENANT`` unless a caller opens a
``tenant_scope``.

Determinism: no wall-clock, no randomness - the value is whatever the caller
bound, so replay under the same scope reproduces the same attribution.
"""

from __future__ import annotations

import contextvars
import re
from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional

DEFAULT_TENANT = "default"
# Matches the console's X-Tenant-ID validation so a claim can never carry a
# path-traversal / injection payload into an attribution.
_TENANT_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

_tenant: contextvars.ContextVar[str] = contextvars.ContextVar("pi_tenant_id", default=DEFAULT_TENANT)


def _normalize(tenant_id: Optional[str]) -> str:
    return tenant_id if (tenant_id and _TENANT_RE.match(tenant_id)) else DEFAULT_TENANT


def current_tenant() -> str:
    """The tenant bound to the current async task / thread context."""
    return _tenant.get()


def set_tenant(tenant_id: Optional[str]) -> contextvars.Token:
    """Bind the current tenant; returns a token for reset_tenant()."""
    return _tenant.set(_normalize(tenant_id))


def reset_tenant(token: contextvars.Token) -> None:
    _tenant.reset(token)


@contextmanager
def tenant_scope(tenant_id: Optional[str]) -> Iterator[str]:
    """Bind a tenant for the duration of the block (restores on exit)."""
    token = set_tenant(tenant_id)
    try:
        yield current_tenant()
    finally:
        reset_tenant(token)


def tenant_from_claims(claims: Optional[Dict[str, Any]]) -> str:
    """Extract the trusted tenant from authenticated JWT claims (or default)."""
    if not claims:
        return DEFAULT_TENANT
    return _normalize(claims.get("tenant_id"))
