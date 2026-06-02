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

Row-level tenant isolation is now in place on both sides:
  * READ: ``execution_trace`` has a ``tenant_id`` column (with in-place legacy
    migration), and the ledger/transparency routes filter every query by the
    caller's ``tenant_id`` JWT claim via ``tenant_scope`` below (admins see all).
  * WRITE: the orchestrator write paths stamp the authenticated tenant onto each
    trace via ``pi_agent_chain.tenant_context`` (bound from the JWT claim in
    ``jwt_validation_middleware`` - never from the forgeable ``X-Tenant-ID``
    header), so audit rows carry their real tenant rather than defaulting.
"""

from __future__ import annotations

import os
from typing import Any, Dict, Optional

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


async def tenant_scope(request: Request) -> Optional[str]:
    """Tenant filter for ledger reads, derived from the authenticated principal.

    Returns:
      * ``None``  -> unrestricted read (an ``admin`` role, or the explicit dev
        opt-out) — caller may see all tenants;
      * ``<tenant_id>`` -> reads MUST be filtered to this tenant only.

    Raises 401 (no principal) or 403 (authenticated but no ``tenant_id`` claim,
    so the request cannot be safely scoped).
    """
    claims = await require_reader(request)
    if not claims:
        # Dev opt-out (require_reader allowed an unauthenticated request).
        return None
    if claims.get("role") == "admin":
        return None
    tenant = claims.get("tenant_id")
    if not tenant:
        raise HTTPException(
            status_code=403,
            detail="token has no tenant_id claim; cannot scope ledger access",
        )
    return str(tenant)
