"""Capabilities router: marketplace + compatibility graph."""

from fastapi import APIRouter, HTTPException, Request

from pi_console.schemas import (
    GetCompatibilityGraphRequest,
    GetCompatibilityGraphResponse,
    ListMarketplaceCapabilitiesRequest,
    ListMarketplaceCapabilitiesResponse,
)
from pi_console.services import CoreAdapter

router = APIRouter()
core_adapter = CoreAdapter()

_MAX_LIMIT = 200
_MAX_OFFSET = 1_000_000


@router.post("/list", response_model=ListMarketplaceCapabilitiesResponse)
async def list_capabilities(
    req: Request, body: ListMarketplaceCapabilitiesRequest
) -> ListMarketplaceCapabilitiesResponse:
    tenant_id: str = getattr(req.state, "tenant_id", "default")
    if body.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    if body.limit < 1 or body.limit > _MAX_LIMIT:
        raise HTTPException(status_code=400, detail=f"limit must be in [1, {_MAX_LIMIT}]")
    if body.offset < 0 or body.offset > _MAX_OFFSET:
        raise HTTPException(status_code=400, detail=f"offset must be in [0, {_MAX_OFFSET}]")
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
