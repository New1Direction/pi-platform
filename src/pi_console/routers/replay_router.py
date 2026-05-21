"""Replay router: get_execution_replay."""

from fastapi import APIRouter, Request

from pi_console.schemas import GetExecutionReplayRequest, GetExecutionReplayResponse
from pi_console.services import CoreAdapter

router = APIRouter()
core_adapter = CoreAdapter()

@router.post("/get", response_model=GetExecutionReplayResponse)
async def get_replay(req: Request, body: GetExecutionReplayRequest) -> GetExecutionReplayResponse:
    return core_adapter.get_execution_replay(
        body.ledger_id,
        from_seq=body.from_sequence,
        to_seq=body.to_sequence,
    )
