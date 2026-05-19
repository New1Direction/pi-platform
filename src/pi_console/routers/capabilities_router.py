"""Capabilities router: marketplace + compatibility graph."""

from fastapi import APIRouter, Request
from typing import Optional
from pi_console.schemas import (
    GetCompatibilityGraphRequest,
    GetCompatibilityGraphResponse,
    ListMarketplaceCapabilitiesRequest,
    ListMarketplaceCapabilitiesResponse,
)
from pi_console.services import CoreAdapter

router = APIRouter()
core_adapter = CoreAdapter()

@router.post("/list", response_model=ListMarketplaceCapabilitiesResponse)
async def list_capabilities(req: Request, body: ListMarketplaceCapabilitiesRequest) -> ListMarketplaceCapabilitiesResponse:
    tenant_id: str = getattr(req.state, "tenant_id", "default")
    if body.tenant_id != tenant_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    return core_adapter.list_capabilities(
        tenant_id=body.tenant_id,
        runtime_filter=body.filter_runtime,
        operation_filter=body.filter_operation,
        limit=body.limit,
        offset=body.offset,
    )

@router.post("/compatibility-graph", response_model=GetCompatibilityGraphResponse)
async def compatibility_graph(req: Request, body: GetCompatibilityGraphRequest) -> GetCompatibilityGraphResponse:
    tenant_id: str = getattr(req.state, "tenant_id", "default")
    if body.tenant_id != tenant_id:
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    return core_adapter.get_compatibility_graph(
        tenant_id=body.tenant_id,
        runtime_filter=body.runtime_filter,
    )
