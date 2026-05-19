# PI Platform — API Reference

This document describes the OpenAPI tool schemas exposed by the PI Console backend. These are the ONLY interfaces between Layer 4 (human interface) and Layers 1-3 (deterministic core).

All endpoints are prefixed with `/api/v1/` and require the `X-Tenant-ID` header.

---

## Endpoints

### `POST /api/v1/compositions/simulate`

Run a deterministic simulation without mutating core state.

**Request** (`SimulateCompositionRequest`):
```json
{
  "composition": {
    "tenant_id": "tenant-001",
    "console_session_id": "sess_abc123",
    "nodes": [{"node_id": "n1", "runtime": "pi-semantic-recon", "operation": "VALIDATE"}],
    "edges": [],
    "global_bounds": {"max_total_nodes": 64, "max_depth": 8, "max_fanout": 16, "max_execution_time_ms": 300000},
    "simulation_only": true,
    "strict": true
  }
}
```

**Response** (`SimulateCompositionResponse`):
```json
{
  "report": {
    "report_id": "sim_xyz",
    "request_id": "ecr_abc",
    "dag_valid": true,
    "bounds_respected": true,
    "policy_violations": [],
    "execution_plan": ["n1"],
    "risk_level": "NONE",
    "replay_safe": true,
    "report_hash": "sha256..."
  },
  "can_execute": true
}
```

### `POST /api/v1/compositions/submit`

Submit an approved composition for execution. Requires explicit user confirmation.

**Request** (`SubmitCompositionRequest`):
```json
{
  "composition": { ... },
  "user_confirmation": true
}
```

**Response** (`SubmitCompositionResponse`):
```json
{
  "request_id": "ecr_abc",
  "accepted": true,
  "status": "QUEUED",
  "message": "Composition accepted",
  "core_ledger_id": "ledger_xyz"
}
```

### `POST /api/v1/compositions/translate`

(Internal) Translate natural language to `ExplicitCompositionRequest`. LLM-only. Never executes.

**Request** (`ChatTranslationRequest`):
```json
{
  "console_session_id": "sess_abc",
  "tenant_id": "tenant-001",
  "user_message": "Validate all API endpoints"
}
```

**Response** (`ChatTranslationResponse`):
```json
{
  "proposed_composition": { ... },
  "translation_valid": true,
  "requires_user_approval": true
}
```

### `GET /api/v1/replays/{ledger_id}`

Fetch execution replay events.

**Response** (`GetExecutionReplayResponse`):
```json
{
  "ledger_id": "ledger_xyz",
  "events": [
    {"sequence_number": 1, "event_type": "ARTIFACT_RECEIVED", "event_hash": "...", "previous_hash": ""}
  ],
  "integrity_verified": true,
  "total_events": 42
}
```

### `GET /api/v1/capabilities`

List marketplace capabilities.

**Query**: `?tenant_id=tenant-001&limit=50&offset=0`

**Response** (`ListMarketplaceCapabilitiesResponse`):
```json
{
  "capabilities": [
    {"capability_id": "cap_1", "runtime": "pi-semantic-recon", "operation": "VALIDATE", "trust_tier": "GOVERNED"}
  ],
  "total": 1, "limit": 50, "offset": 0
}
```

### `GET /api/v1/capabilities/compatibility`

Fetch capability compatibility graph.

**Response** (`GetCompatibilityGraphResponse`):
```json
{
  "nodes": [{"capability_id": "cap_1", "runtime": "pi-semantic-recon", "trust_tier": "GOVERNED"}],
  "edges": [{"source_capability": "cap_1", "target_capability": "cap_2", "compatible": true, "reason": ""}]
}
```

### `GET /api/v1/tenant/quota`

Get tenant quota status.

**Response** (`GetTenantQuotaStatusResponse`):
```json
{
  "quota": {
    "tenant_id": "tenant-001",
    "compositions_submitted": 12,
    "quota_exceeded": false
  }
}
```

### `GET /api/v1/audit`

Query audit log.

**Query**: `?tenant_id=tenant-001&limit=100`

**Response** (`GetAuditLogResponse`):
```json
{
  "entries": [
    {"entry_id": "aud_1", "action": "COMPOSITION_SUBMITTED", "structured_request": { ... }}
  ],
  "total": 42
}
```

---

## Error Codes

| Code | Meaning |
|------|---------|
| `400` | Malformed request / schema validation failure |
| `403` | Tenant mismatch / missing user confirmation / policy DENY |
| `404` | Ledger / capability / resource not found |
| `422` | ExplicitCompositionRequest validation failed |
| `429` | Quota exceeded / rate limited |
| `500` | Core execution failure (receipt status FAIL) |
| `503` | Core unreachable / shard capacity exceeded |
