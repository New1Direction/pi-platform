"""Session router: create, get, list, terminate."""

from fastapi import APIRouter, HTTPException, Request

from pi_console.schemas import ConsoleSession
from pi_console.services import ConsoleSessionStore, _safe_tenant_id

router = APIRouter()
session_store = ConsoleSessionStore()


@router.post("/create", response_model=ConsoleSession)
async def create_session(
    req: Request,
    tenant_id: str,
    llm_enabled: bool = False,
    llm_provider: str = "",
) -> ConsoleSession:
    """Create a console session for the caller's tenant.

    The ``tenant_id`` query parameter must match ``req.state.tenant_id``
    (set by ``tenant_injection_middleware``). This blocks an authenticated
    caller from minting a session for an arbitrary other tenant.
    """
    header_tenant = getattr(req.state, "tenant_id", None)
    # The middleware already format-validates X-Tenant-ID. We still validate
    # the query value defensively before the IDOR check.
    try:
        body_tenant = _safe_tenant_id(tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if header_tenant is None or body_tenant != header_tenant:
        raise HTTPException(
            status_code=403,
            detail="tenant_mismatch: query tenant_id != X-Tenant-ID",
        )

    provider = llm_provider or None
    return session_store.create(
        tenant_id=body_tenant,
        llm_enabled=llm_enabled,
        llm_provider=provider,
    )


@router.get("/{session_id}", response_model=ConsoleSession)
async def get_session(req: Request, session_id: str) -> ConsoleSession:
    session = session_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    header_tenant = getattr(req.state, "tenant_id", None)
    if session.tenant_id != header_tenant:
        # Don't leak existence of sessions belonging to other tenants.
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.get("/", response_model=list[ConsoleSession])
async def list_sessions(req: Request) -> list[ConsoleSession]:
    header_tenant = getattr(req.state, "tenant_id", None)
    return [s for s in session_store.list_active() if s.tenant_id == header_tenant]
