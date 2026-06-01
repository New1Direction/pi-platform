"""Fail-closed authentication gate for sensitive console read surfaces.

The ledger and transparency routers expose every tenant's execution audit data
(traces, raw outputs, llm seeds, risk scores, causality DAGs). Authentication on
the console is middleware-based and was opt-in, so with the shipped default
(``PI_SECRET_JWT`` unset) these endpoints served that data to anyone who could
reach the server.

``require_reader`` refuses access unless the request carries a valid principal
(a JWT validated by ``jwt_validation_middleware``, which sets
``request.state.jwt_claims``). If no auth is configured at all, access is denied
(fail closed) unless an operator *explicitly* opts out for local development via
``PI_CONSOLE_ALLOW_UNAUTHENTICATED=1``.

NOTE (follow-up, not closed here): the ``execution_trace`` ledger has no
``tenant_id`` column, so reads cannot yet be scoped per-tenant. This gate closes
the unauthenticated-access hole; row-level tenant isolation requires a schema
migration (add ``tenant_id``, populate on write, filter by the caller's claim
unless an admin role) plus RBAC enforcement on these routes.
"""

from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import HTTPException, Request

_ALLOW_UNAUTH_ENV = "PI_CONSOLE_ALLOW_UNAUTHENTICATED"


def _unauthenticated_allowed() -> bool:
    return os.getenv(_ALLOW_UNAUTH_ENV, "").strip().lower() in ("1", "true", "yes", "on")


async def require_reader(request: Request) -> Dict[str, Any]:
    """Fail-closed dependency for sensitive read endpoints.

    Returns the authenticated claims, or raises 401. Never serves data to an
    unauthenticated caller unless the explicit dev opt-out is set.
    """
    claims = getattr(request.state, "jwt_claims", None)
    if isinstance(claims, dict):
        return claims
    if _unauthenticated_allowed():
        return {}
    raise HTTPException(
        status_code=401,
        detail=(
            "authentication required: configure PI_SECRET_JWT and present a valid "
            "bearer token to read ledger/transparency data. "
            f"(Local dev only: set {_ALLOW_UNAUTH_ENV}=1 to bypass — never in production.)"
        ),
    )
