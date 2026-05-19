"""Composition router: simulate, submit, translate (chat mode)."""

from fastapi import APIRouter, HTTPException, Request
from datetime import datetime, timezone
from pathlib import Path

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
            user_ip=req.client.host or "",
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
            user_ip=req.client.host or "",
        )
    )
    return result

@router.post("/translate-chat", response_model=ChatTranslationResponse)
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
