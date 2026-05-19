"""Session router: create, get, list, terminate."""

from fastapi import APIRouter, HTTPException
from pi_console.schemas import ConsoleSession
from pi_console.services import ConsoleSessionStore

router = APIRouter()
session_store = ConsoleSessionStore()

@router.post("/create", response_model=ConsoleSession)
async def create_session(tenant_id: str, llm_enabled: bool = False, llm_provider: str = "") -> ConsoleSession:
    provider = llm_provider or None
    return session_store.create(tenant_id=tenant_id, llm_enabled=llm_enabled, llm_provider=provider)

@router.get("/{session_id}", response_model=ConsoleSession)
async def get_session(session_id: str) -> ConsoleSession:
    session = session_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session

@router.get("/", response_model=list[ConsoleSession])
async def list_sessions() -> list[ConsoleSession]:
    return session_store.list_active()
