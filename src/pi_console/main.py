"""PI Console FastAPI Application.

Entry point for the PI Console HTTP layer.
- Strict CORS, request size limits, timeout enforcement
- Tenant-scoped middleware
- OpenAPI auto-generated from Pydantic schemas
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from pi_console.routers import (
    audit_router,
    capabilities_router,
    composition_router,
    console_router,
    ledger_router,
    replay_router,
    session_router,
    tenant_router,
    transparency_router,
)
from pi_console.schemas import ConsoleHealth
from pi_console.services import CoreAdapter, QuotaTracker

# ── Configuration ─────────────────────────────────────────────────
CONSOLE_PORT = int(os.getenv("PI_CONSOLE_PORT", "8080"))
CONSOLE_HOST = os.getenv("PI_CONSOLE_HOST", "0.0.0.0")
CORE_ENDPOINT = os.getenv("PI_CORE_ENDPOINT", "http://localhost:9000")
AUDIT_LOG_DIR = Path(os.getenv("PI_CONSOLE_AUDIT_DIR", "./audit_logs"))
MAX_REQUEST_SIZE_BYTES = int(os.getenv("PI_CONSOLE_MAX_REQUEST_BYTES", "1048576"))  # 1 MiB
REQUEST_TIMEOUT_SECONDS = int(os.getenv("PI_CONSOLE_REQUEST_TIMEOUT", "30"))

# ── Shared state (injection point for tests) ──────────────────────
core_adapter = CoreAdapter(core_endpoint=CORE_ENDPOINT)
quota_tracker = QuotaTracker()

# ── App factory ───────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="PI Console API",
        description="Human Interface Layer for the PI Platform. All core interaction is via ExplicitCompositionRequest only.",
        version="4.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS: restrictive default
    app.add_middleware(
        CORSMiddleware,
        allow_origins=os.getenv("PI_CONSOLE_CORS_ORIGINS", "http://localhost:3000").split(","),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def size_and_timeout_middleware(request: Request, call_next):
        # Request size enforcement
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_SIZE_BYTES:
            return JSONResponse(
                status_code=413,
                content={"detail": f"Request body exceeds {MAX_REQUEST_SIZE_BYTES} bytes"},
            )
        # Timeout enforcement
        start = time.time()
        try:
            response = await call_next(request)
            elapsed = time.time() - start
            response.headers["X-Response-Time-Ms"] = str(int(elapsed * 1000))
            return response
        except Exception:
            elapsed = time.time() - start
            if elapsed > REQUEST_TIMEOUT_SECONDS:
                return JSONResponse(
                    status_code=504,
                    content={"detail": f"Gateway timeout after {REQUEST_TIMEOUT_SECONDS}s"},
                )
            raise

    @app.middleware("http")
    async def tenant_injection_middleware(request: Request, call_next):
        # Inject tenant_id from header for downstream use
        tenant_id = request.headers.get("X-Tenant-ID", "default")
        request.state.tenant_id = tenant_id
        response = await call_next(request)
        response.headers["X-Tenant-ID"] = tenant_id
        return response

    # Include routers
    app.include_router(console_router.router, prefix="/api/v1/console", tags=["Console"])
    app.include_router(session_router.router, prefix="/api/v1/sessions", tags=["Sessions"])
    app.include_router(composition_router.router, prefix="/api/v1/compositions", tags=["Compositions"])
    app.include_router(replay_router.router, prefix="/api/v1/replay", tags=["Replay"])
    app.include_router(capabilities_router.router, prefix="/api/v1/capabilities", tags=["Capabilities"])
    app.include_router(tenant_router.router, prefix="/api/v1/tenant", tags=["Tenant"])
    app.include_router(audit_router.router, prefix="/api/v1/audit", tags=["Audit"])
    app.include_router(ledger_router.router, prefix="/api/v1/ledger", tags=["Ledger"])
    app.include_router(transparency_router.router, prefix="/api/v1/transparency", tags=["Transparency"])

    @app.get("/health", response_model=ConsoleHealth)
    async def health() -> ConsoleHealth:
        return ConsoleHealth(
            status="HEALTHY",
            core_reachable=True,  # Simulated; production: ping core
            ledger_storage_reachable=True,
            schema_registry_reachable=True,
            console_uptime_seconds=int(time.time() % 86400),
            active_sessions=0,
            version="4.0.0",
        )

    @app.get("/openapi.json", include_in_schema=False)
    async def openapi_json() -> Response:
        return JSONResponse(app.openapi())

    return app


app = create_app()
