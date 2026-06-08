# Ledger & Replay

The ledger is the platform's source of truth for *what happened*. Every node
execution is appended as an `execution_trace` row, hash-chained so the history is
tamper-evident and deterministically replayable.

## The trace store

`StateLedger` owns a SQLite table `execution_trace`:

| Column | Notes |
|--------|-------|
| `trace_id` | The composition's `core_ledger_id`. |
| `node_name` | `runtime:operation:node_id`. |
| `raw_output` | The serialized `OrchestratorOutput` (routed agent, risk, findings). |
| `input_payload_hash` | SHA-256 of the node context. |
| `is_valid_type` / `is_finding` | Success + finding flags. |
| `tenant_id` | Authenticated tenant (stamped from JWT claims, not the header). |

## Replay & integrity

`POST /api/v1/replay/get` re-walks the chained events for a ledger id and returns
`integrity_verified`. Because traces are content-addressed (`event_hash` derived from
content, linked via `previous_hash`), any mutation breaks the chain and integrity
fails.

!!! note "Determinism"
    Replay is meaningful only because execution is deterministic — fixed seed
    (`llm_seed=1337`), zero temperature, pure agents, keyword routing. The same input
    reproduces the same receipt.

## The shared-store gotcha

The single most common ledger problem is the **reader and writer pointing at
different SQLite files**:

- **Writer** — `StateLedger`, keyed off `PI_STATE_LEDGER_PATH`.
- **Reader** — `ledger_router`, uses `PI_LEDGER_DB_PATH` if set, else falls back to
  `PI_STATE_LEDGER_PATH`, else the legacy default `pi_audit_ledger.db`.

If those resolve to different files, the writer creates `execution_trace` in one DB
and the reader queries another — yielding `no such table: execution_trace` and an
empty [Ledger tab](../console/ledger.md). Set `PI_STATE_LEDGER_PATH` for the backend
process and both sides agree.

!!! tip "Multiple adapters, one file"
    Some routers instantiate their own `CoreAdapter` at import time. Pointing them all
    at one `PI_STATE_LEDGER_PATH` is what makes a submit in one request visible to a
    replay/ledger read in the next.
