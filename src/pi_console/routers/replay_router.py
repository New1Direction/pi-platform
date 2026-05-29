"""Replay router: get_execution_replay."""

from fastapi import APIRouter, HTTPException, Request

from pi_console.schemas import GetExecutionReplayRequest, GetExecutionReplayResponse
from pi_console.services import CoreAdapter

router = APIRouter()
core_adapter = CoreAdapter()

_MAX_REPLAY_RANGE = 100_000  # events per call


@router.post("/get", response_model=GetExecutionReplayResponse)
async def get_replay(req: Request, body: GetExecutionReplayRequest) -> GetExecutionReplayResponse:
    f = body.from_sequence if body.from_sequence is not None else 0
    t = body.to_sequence if body.to_sequence is not None else f + _MAX_REPLAY_RANGE
    if f < 0 or t < 0:
        raise HTTPException(status_code=400, detail="sequence numbers must be non-negative")
    if t < f:
        raise HTTPException(status_code=400, detail="to_sequence must be >= from_sequence")
    if t - f > _MAX_REPLAY_RANGE:
        raise HTTPException(
            status_code=400,
            detail=f"replay range too large: max {_MAX_REPLAY_RANGE} events per call",
        )
    return core_adapter.get_execution_replay(
        body.ledger_id,
        from_seq=body.from_sequence,
        to_seq=body.to_sequence,
    )
