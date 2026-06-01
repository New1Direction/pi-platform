"""Composition router: simulate, submit, translate (chat mode)."""

import ipaddress
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request

from pi_console.schemas import (
    AuditLogEntry,
    ChatTranslationRequest,
    ChatTranslationResponse,
    CompositionNode,
    ExplicitCompositionRequest,
    SimulateCompositionRequest,
    SimulateCompositionResponse,
    SubmitCompositionRequest,
    SubmitCompositionResponse,
)
from pi_console.services import ConsoleAuditStore, ConsoleSessionStore, CoreAdapter, QuotaTracker

router = APIRouter()
core_adapter = CoreAdapter()
quota_tracker = QuotaTracker()
audit_store = ConsoleAuditStore(Path("./audit_logs"))
session_store = ConsoleSessionStore()


def _trusted_proxy(remote: str) -> bool:
    """Return True if X-Forwarded-For should be honoured for this peer."""
    trusted = os.getenv("PI_TRUSTED_PROXY_CIDRS", "").strip()
    if not trusted or not remote:
        return False
    try:
        peer = ipaddress.ip_address(remote)
    except ValueError:
        return False
    for cidr in (c.strip() for c in trusted.split(",")):
        if not cidr:
            continue
        try:
            if peer in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _client_ip(req: Request) -> str:
    """
    Resolve client IP without trusting forged X-Forwarded-For.

    Default: ``req.client.host`` only (the actual TCP peer).
    If ``PI_TRUSTED_PROXY_CIDRS`` is set AND the peer falls inside one of
    those CIDRs, we read the left-most IP from X-Forwarded-For instead.
    """
    peer = req.client.host if req.client else ""
    if _trusted_proxy(peer):
        xff = req.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return peer or ""


@router.post("/simulate", response_model=SimulateCompositionResponse)
async def simulate(req: Request, body: SimulateCompositionRequest) -> SimulateCompositionResponse:
    tenant_id: str = getattr(req.state, "tenant_id", "default")
    comp = body.composition
    # Enforce tenant match
    if comp.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch in composition")
    quota = quota_tracker.record_simulation(tenant_id)
    if quota.quota_exceeded:
        raise HTTPException(status_code=429, detail="Simulation quota exceeded")
    result = core_adapter.simulate(comp)
    audit_store.append(
        AuditLogEntry(
            tenant_id=tenant_id,
            console_session_id=comp.console_session_id,
            request_id=comp.request_id,
            action="COMPOSITION_SIMULATED",
            structured_request=comp.model_dump(),
            response_status="SIMULATED",
            user_ip=_client_ip(req),
        )
    )
    return result


@router.post("/submit", response_model=SubmitCompositionResponse)
async def submit(req: Request, body: SubmitCompositionRequest) -> SubmitCompositionResponse:
    tenant_id: str = getattr(req.state, "tenant_id", "default")
    comp = body.composition
    if comp.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch in composition")
    if not body.user_confirmation:
        raise HTTPException(status_code=400, detail="User confirmation required")
    # Ensure simulation passed
    sim = core_adapter.simulate(comp)
    if not sim.can_execute:
        raise HTTPException(status_code=400, detail="Composition failed simulation; cannot submit")
    quota = quota_tracker.record_composition(tenant_id)
    if quota.quota_exceeded:
        raise HTTPException(status_code=429, detail="Composition quota exceeded")
    result = core_adapter.submit(comp)
    session_store.mark_approved(comp.console_session_id, comp.request_id)
    audit_store.append(
        AuditLogEntry(
            tenant_id=tenant_id,
            console_session_id=comp.console_session_id,
            request_id=comp.request_id,
            action="COMPOSITION_SUBMITTED",
            structured_request=comp.model_dump(),
            response_status=result.status,
            user_ip=_client_ip(req),
        )
    )
    return result


@router.post(
    "/translate-chat",
    response_model=ChatTranslationResponse,
    summary="Translate natural language → composition (experimental)",
    description=(
        "**Experimental.** Returns a deterministic single-node demo composition. "
        "Production NLP translation requires an LLM provider configured on the "
        "session (`llm_enabled=true`) — no LLM is invoked from this endpoint yet."
    ),
)
async def translate_chat(req: Request, body: ChatTranslationRequest) -> ChatTranslationResponse:
    tenant_id: str = getattr(req.state, "tenant_id", "default")
    if body.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Tenant mismatch")
    # Chat translation is console-internal. If LLM is not enabled, reject.
    session = session_store.get(body.console_session_id)
    if not session or not session.llm_enabled:
        return ChatTranslationResponse(
            translation_valid=False,
            validation_errors=["LLM not enabled for this session"],
            explanation="Enable LLM in session settings to use chat translation.",
            requires_user_approval=True,
        )
    # In a real implementation, call the configured LLM here (still inside console boundary).
    # For deterministic reference: simulate a simple mapping for demo purposes.
    proposed = ExplicitCompositionRequest(
        tenant_id=tenant_id,
        console_session_id=body.console_session_id,
        nodes=[
            CompositionNode(
                node_id="node_1",
                runtime="pi-semantic-recon",
                operation="VALIDATE",
                artifacts=[],
                required_schema_version="1.0.0",
                bounds={"max_depth": 8, "max_fanout": 16},
                dependencies=[],
            )
        ],
        edges=[],
        simulation_only=True,
        approved_by_user=False,
    )
    return ChatTranslationResponse(
        proposed_composition=proposed,
        translation_valid=True,
        validation_errors=[],
        explanation="Translated natural language into a single-node VALIDATE composition on pi-semantic-recon.",
        requires_user_approval=True,
    )
