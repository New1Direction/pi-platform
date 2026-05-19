"""Tenant router: quota status."""

from fastapi import APIRouter, HTTPException, Request
from pi_console.schemas import GetTenantQuotaStatusRequest, GetTenantQuotaStatusResponse
from pi_console.services import QuotaTracker

router = APIRouter()
quota_tracker = QuotaTracker()

@router.post("/quota", response_model=GetTenantQuotaStatusResponse)
async def get_quota(req: Request, body: GetTenantQuotaStatusRequest) -> GetTenantQuotaStatusResponse:
    tenant_id: str = getattr(req.state, "tenant_id", "default")
    if body.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    quota = quota_tracker.get(body.tenant_id)
    return GetTenantQuotaStatusResponse(quota=quota)
