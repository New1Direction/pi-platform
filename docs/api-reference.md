# API Reference

The PI Console backend (`pi_console.main:app`) exposes the only interface between the
human layer (L4) and the deterministic core (L1–L3).

- All endpoints are prefixed with `/api/v1/`.
- All require the `X-Tenant-ID` header (must match `[A-Za-z0-9_-]{1,64}`).
- JWT and request signing are opt-in (`PI_SECRET_JWT`, `PI_SECRET_REQUEST_SIGNING`).
- `GET /health` (unprefixed) is the liveness probe.

!!! note "Verify against the live schema"
    This page is generated from the running service. The authoritative, always-current
    schema is `GET /openapi.json` (or `/docs` for Swagger UI).

## Compositions

### `POST /api/v1/compositions/simulate`

Deterministic dry run — validates the DAG, bounds, policy, and risk without mutating
core state or executing agents.

```json
{ "composition": { "tenant_id": "…", "console_session_id": "…", "nodes": [ … ], "edges": [], "simulation_only": true, "strict": true } }
```

Response: `{ "report": { "dag_valid", "bounds_respected", "risk_level", "execution_plan", "replay_safe", "report_hash" }, "can_execute": true }`

### `POST /api/v1/compositions/submit`

Execute an approved composition. Body: `{ "composition": { … }, "user_confirmation": true }`.

Response (`SubmitCompositionResponse`):

```json
{ "request_id": "…", "accepted": true, "status": "ACCEPTED", "message": "…", "core_ledger_id": "ledger_…" }
```

Each node routes on its **artifact goal** (see [routing](architecture/orchestrator-routing.md)).

### `POST /api/v1/compositions/translate-chat`

LLM-only translation of natural language → a proposed `ExplicitCompositionRequest`.
Never executes. Body: `{ "console_session_id", "tenant_id", "user_message" }`.

## Capabilities

### `POST /api/v1/capabilities/list`

List the live micro-agent registry. Body: `{ "tenant_id", "limit", "offset" }`.

```json
{ "capabilities": [ { "capability_id": "cap_pigitsecscanner", "runtime": "pi-extension-governor", "operation": "SANDBOX", "trust_tier": "GOVERNED", "compatibility_tags": ["dependency scan", …] } ], "total": 248 }
```

### `POST /api/v1/capabilities/compatibility-graph`

Derive a compatibility graph (agents sharing a keyword are compatible). Body:
`{ "tenant_id" }`. Bounded to 32 nodes.

## Replay

### `POST /api/v1/replay/get`

Fetch the hash-chained events for a ledger id. Body: `{ "ledger_id" }`.

```json
{ "ledger_id": "ledger_…", "events": [ { "sequence_number": 1, "event_type": "…", "event_hash": "…", "previous_hash": "" } ], "integrity_verified": true, "total_events": 1 }
```

## Ledger

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/ledger/traces` | Paginated trace list (`?limit&offset&node_name&success&search&min_risk`). |
| `GET` | `/api/v1/ledger/trace/{trace_id}` | Full trace incl. `raw_output` / `parsed_output`. |
| `GET` | `/api/v1/ledger/summary` | Aggregate stats: totals, success rate, avg risk, anomalies. |

Ledger endpoints are gated fail-closed (a valid reader principal is required). See
the [shared-store note](architecture/ledger-replay.md).

## Agent Forge

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/forge/generate` | Generate agent code (header `x-anthropic-key`, BYOK). |
| `POST` | `/api/v1/forge/audit` | Static audit (syntax + dangerous-pattern + structural). |
| `POST` | `/api/v1/forge/save` | Re-audit then save to `pending/` as `UNVERIFIED` (`422` if audit fails). |

See [Agent Forge](console/forge.md).

## Sessions, Tenant, Audit, Transparency

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/api/v1/sessions/create` | Create a session (`?tenant_id=`; must match header). |
| `GET`  | `/api/v1/sessions/{session_id}` | Fetch a session. |
| `POST` | `/api/v1/tenant/quota` | Tenant quota status. Body: `{ "tenant_id" }`. |
| `POST` | `/api/v1/audit/log` | Query audit log (`body.tenant_id` must equal `X-Tenant-ID`). |
| `GET`  | `/api/v1/transparency/lineage/{trace_id}` | Lineage for a trace. |
| `GET`  | `/api/v1/transparency/replay/binary-search` | Binary-search replay diagnostics. |
| `GET`  | `/api/v1/console/health` | Console health detail. |

## Error codes

| Code | Meaning |
|------|---------|
| `400` | Malformed request / invalid `X-Tenant-ID` |
| `401` | Missing/invalid JWT or request signature (when required) |
| `403` | Tenant mismatch / missing confirmation / policy DENY |
| `413` | Request body exceeds the configured limit |
| `422` | Schema validation failed / Forge audit failed |
| `429` | Quota exceeded / rate limited |
| `500` | Core execution failure |
| `504` | Request exceeded the timeout |
