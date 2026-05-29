"""Console router: health, config, status."""

from fastapi import APIRouter

from pi_console.schemas import ConsoleHealth

router = APIRouter()

@router.get("/health")
async def console_health() -> ConsoleHealth:
    return ConsoleHealth(status="HEALTHY", version="4.0.0")
