"""Audit router: get_audit_log."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from pi_console.schemas import GetAuditLogRequest, GetAuditLogResponse
from pi_console.services import ConsoleAuditStore, _safe_tenant_id

router = APIRouter()
audit_store = ConsoleAuditStore(Path("./audit_logs"))


@router.post("/log", response_model=GetAuditLogResponse)
async def get_audit_log(req: Request, body: GetAuditLogRequest) -> GetAuditLogResponse:
    tenant_id: str = getattr(req.state, "tenant_id", "default")
    # Defence-in-depth: also format-validate the body tenant_id. The path
    # construction in services._path already guards, but failing fast here
    # gives a 400 instead of an opaque 500 from deeper validation.
    try:
        body_tenant = _safe_tenant_id(body.tenant_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if body_tenant != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    entries = audit_store.query(
        tenant_id=body.tenant_id,
        console_session_id=body.console_session_id,
        action_filter=body.action_filter,
        from_timestamp=body.from_timestamp,
        to_timestamp=body.to_timestamp,
        limit=body.limit,
        offset=body.offset,
    )
    total = audit_store.count(
        tenant_id=body.tenant_id,
        console_session_id=body.console_session_id,
        action_filter=body.action_filter,
        from_timestamp=body.from_timestamp,
        to_timestamp=body.to_timestamp,
    )
    return GetAuditLogResponse(entries=entries, total=total)
