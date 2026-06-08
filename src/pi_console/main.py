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

from fastapi import Depends, FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from pi_agent_chain.tenant_context import reset_tenant, set_tenant, tenant_from_claims
from pi_console.auth_guard import require_reader
from pi_console.routers import (
    agent_forge_router,
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
from pi_console.services import _TENANT_ID_RE, CoreAdapter, QuotaTracker
from pi_production.security.auth import (
    AuthenticationError,
    JWTToken,
    RequestSigner,
    SignatureError,
)

# ── Configuration ─────────────────────────────────────────────────
CONSOLE_PORT = int(os.getenv("PI_CONSOLE_PORT", "8080"))
CONSOLE_HOST = os.getenv("PI_CONSOLE_HOST", "0.0.0.0")
CORE_ENDPOINT = os.getenv("PI_CORE_ENDPOINT", "http://localhost:9000")
AUDIT_LOG_DIR = Path(os.getenv("PI_CONSOLE_AUDIT_DIR", "./audit_logs"))
MAX_REQUEST_SIZE_BYTES = int(os.getenv("PI_CONSOLE_MAX_REQUEST_BYTES", "1048576"))  # 1 MiB
REQUEST_TIMEOUT_SECONDS = int(os.getenv("PI_CONSOLE_REQUEST_TIMEOUT", "30"))

# JWT is opt-in. If PI_SECRET_JWT is unset, no token validation happens.
# If set without PI_REQUIRE_JWT=1, present tokens are validated but missing
# ones are allowed (useful for incremental rollout). With PI_REQUIRE_JWT=1
# every /api/v1/* path requires a valid bearer token.
JWT_SECRET = os.getenv("PI_SECRET_JWT")
JWT_REQUIRED = os.getenv("PI_REQUIRE_JWT") == "1"
_JWT_EXEMPT_PREFIXES = ("/health", "/docs", "/redoc", "/openapi.json")

# Request signing mirrors the JWT pattern: when PI_SECRET_REQUEST_SIGNING is
# set, signatures on present X-PI-Signature headers are verified. Set
# PI_REQUIRE_REQUEST_SIGNING=1 to also reject requests without a signature.
SIGNING_SECRET = os.getenv("PI_SECRET_REQUEST_SIGNING")
SIGNING_REQUIRED = os.getenv("PI_REQUIRE_REQUEST_SIGNING") == "1"

# ── Shared state (injection point for tests) ──────────────────────
core_adapter = CoreAdapter(core_endpoint=CORE_ENDPOINT)
quota_tracker = QuotaTracker()
_BOOT_TIME = time.time()

# ── App factory ───────────────────────────────────────────────────


def create_app() -> FastAPI:
    app = FastAPI(
        title="PI Console API",
        description="Human Interface Layer for the PI Platform. All core interaction is via ExplicitCompositionRequest only.",
        version="4.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # CORS: restrictive default. Trim each origin so spaces in the env var
    # (e.g. "http://a.com, http://b.com") don't silently lock everyone out.
    _cors_origins = [
        o.strip() for o in os.getenv("PI_CONSOLE_CORS_ORIGINS", "http://localhost:3000").split(",") if o.strip()
    ]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
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

    jwt_codec = JWTToken(JWT_SECRET) if JWT_SECRET else None
    request_signer = RequestSigner(SIGNING_SECRET) if SIGNING_SECRET else None

    @app.middleware("http")
    async def request_signature_middleware(request: Request, call_next):
        # Exempt health/docs paths and idempotent reads when not strictly
        # required. The body has to be buffered to verify the hash; we
        # repackage the receive channel so downstream handlers can still
        # read it.
        path = request.url.path
        if any(path.startswith(p) for p in _JWT_EXEMPT_PREFIXES):
            return await call_next(request)

        signature = request.headers.get("X-PI-Signature", "")
        timestamp = request.headers.get("X-PI-Timestamp", "")
        tenant_id = request.headers.get("X-Tenant-ID", "default")

        if not signature:
            if request_signer is not None and SIGNING_REQUIRED:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "missing X-PI-Signature"},
                )
            return await call_next(request)

        if request_signer is None:
            return JSONResponse(
                status_code=401,
                content={"detail": "request signing not configured on this server"},
            )
        try:
            ts_int = int(timestamp)
        except (TypeError, ValueError):
            return JSONResponse(
                status_code=401,
                content={"detail": "invalid or missing X-PI-Timestamp"},
            )

        body = await request.body()
        try:
            request_signer.verify(
                signature=signature,
                method=request.method,
                path=path,
                timestamp=ts_int,
                tenant_id=tenant_id,
                body=body,
            )
        except SignatureError as e:
            return JSONResponse(status_code=401, content={"detail": str(e)})

        # Reseed the receive channel since we consumed it via request.body().
        async def _replay_receive():
            return {"type": "http.request", "body": body, "more_body": False}

        request._receive = _replay_receive
        return await call_next(request)

    @app.middleware("http")
    async def jwt_validation_middleware(request: Request, call_next):
        # Exempt health/docs and (when not strictly required) any path that
        # isn't under /api/v1. The middleware is opt-in via PI_SECRET_JWT.
        path = request.url.path
        if any(path.startswith(p) for p in _JWT_EXEMPT_PREFIXES):
            request.state.jwt_claims = None
            return await call_next(request)

        auth_header = request.headers.get("Authorization", "")
        token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""

        if not token:
            if jwt_codec is not None and JWT_REQUIRED:
                return JSONResponse(
                    status_code=401,
                    content={"detail": "missing bearer token"},
                )
            request.state.jwt_claims = None
            return await call_next(request)

        if jwt_codec is None:
            # Token presented but no secret configured — surface this loudly
            # rather than silently accepting.
            return JSONResponse(
                status_code=401,
                content={"detail": "JWT not configured on this server"},
            )

        try:
            request.state.jwt_claims = jwt_codec.decode(token)
        except AuthenticationError as e:
            return JSONResponse(status_code=401, content={"detail": str(e)})
        # Bind the AUTHENTICATED tenant (from the JWT claim, not the forgeable
        # X-Tenant-ID header) for the duration of this request, so any
        # ExecutionTrace written downstream is attributed to the right tenant.
        ctx_token = set_tenant(tenant_from_claims(request.state.jwt_claims))
        try:
            return await call_next(request)
        finally:
            reset_tenant(ctx_token)

    @app.middleware("http")
    async def tenant_injection_middleware(request: Request, call_next):
        # Inject tenant_id from header. Reject anything that could traverse
        # paths downstream (the value flows into audit log filenames in
        # ConsoleAuditStore._path).
        raw = request.headers.get("X-Tenant-ID", "default")
        if not _TENANT_ID_RE.match(raw):
            return JSONResponse(
                status_code=400,
                content={"detail": "invalid X-Tenant-ID: must match [A-Za-z0-9_-]{1,64}"},
            )
        request.state.tenant_id = raw
        response = await call_next(request)
        response.headers["X-Tenant-ID"] = raw
        return response

    # Include routers
    app.include_router(agent_forge_router.router, prefix="/api/v1/forge", tags=["AgentForge"])
    app.include_router(console_router.router, prefix="/api/v1/console", tags=["Console"])
    app.include_router(session_router.router, prefix="/api/v1/sessions", tags=["Sessions"])
    app.include_router(composition_router.router, prefix="/api/v1/compositions", tags=["Compositions"])
    app.include_router(replay_router.router, prefix="/api/v1/replay", tags=["Replay"])
    app.include_router(capabilities_router.router, prefix="/api/v1/capabilities", tags=["Capabilities"])
    app.include_router(tenant_router.router, prefix="/api/v1/tenant", tags=["Tenant"])
    app.include_router(audit_router.router, prefix="/api/v1/audit", tags=["Audit"])
    # Ledger + transparency expose cross-tenant execution audit data. Gate them
    # fail-closed: a valid authenticated principal is required (see auth_guard).
    app.include_router(
        ledger_router.router,
        prefix="/api/v1/ledger",
        tags=["Ledger"],
        dependencies=[Depends(require_reader)],
    )
    app.include_router(
        transparency_router.router,
        prefix="/api/v1/transparency",
        tags=["Transparency"],
        dependencies=[Depends(require_reader)],
    )

    @app.get("/health", response_model=ConsoleHealth)
    async def health() -> ConsoleHealth:
        probe = core_adapter.health_probe()
        all_ok = all(probe.values())
        return ConsoleHealth(
            status="HEALTHY" if all_ok else "DEGRADED",
            core_reachable=probe["core_reachable"],
            ledger_storage_reachable=probe["ledger_storage_reachable"],
            schema_registry_reachable=probe["schema_registry_reachable"],
            console_uptime_seconds=int(time.time() - _BOOT_TIME),
            active_sessions=0,
            version="4.0.0",
        )

    @app.get("/openapi.json", include_in_schema=False)
    async def openapi_json() -> Response:
        return JSONResponse(app.openapi())

    return app


app = create_app()
