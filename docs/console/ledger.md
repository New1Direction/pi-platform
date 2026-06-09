# Battle Log *(Ledger)*

<div class="pi-eyebrow">Was: Ledger</div>

The **Battle Log** is the audit trail: every node execution is written as a hash-chained
`execution_trace` row and surfaced here with its routed agent (creature + name), risk
score, and anomalies.

## Reading the log

- **Battle History** — a bar per run, oldest→newest; height is risk, color is severity
  (green safe · amber elevated · red critical), with an average-risk line. Click a bar to
  open that trace.
- **Trace table** — each row shows the routed agent's creature, risk chip, node, and
  timestamp; click to expand the full hash-chained detail. A small **terrain glyph**
  marks the content-class a classifier *inferred* for the scanned input — an
  [interpretation, not a property of the input](compass.md#interpretation-vs-ground-truth)
  (hover for the classifier that produced it).
- **Compass mode** swaps the KPI strip for the [Governance Compass](compass.md) — a fleet
  *heading* across every run — and adds the **Migratory instincts** readout: the agent
  Types history has taught the field to watch hardest.

## Data sources

| View element | Endpoint |
|--------------|----------|
| Trace list | `GET /api/v1/ledger/traces` |
| Trace detail | `GET /api/v1/ledger/trace/{trace_id}` |
| PC-stats widget / summary | `GET /api/v1/ledger/summary` |

A trace carries the parsed orchestrator output:

```json
{
  "trace_id": "ledger_…",
  "node_name": "pi-extension-governor:SANDBOX:n1",
  "routed_agent": "PiGitSecScanner",
  "risk_score": 75.0,
  "success": true,
  "anomalies_detected": ["unpinned dependency: flask>=1.0"]
}
```

## Integrity

Traces are content-addressed and chained (`event_hash` / `previous_hash`). The
[replay](../architecture/ledger-replay.md) endpoint re-walks the chain and reports
`integrity_verified`.

## The shared-store requirement

!!! warning "Reader and writer must share one SQLite file"
    The writer (`StateLedger`) keys off **`PI_STATE_LEDGER_PATH`**; the reader
    (`ledger_router`) honors an explicit `PI_LEDGER_DB_PATH`, then falls back to
    `PI_STATE_LEDGER_PATH`. If those resolve to different files, the writer creates
    the `execution_trace` table in one DB and the reader queries another — producing
    `no such table: execution_trace` and an empty Ledger tab.

    **Fix:** set `PI_STATE_LEDGER_PATH=/tmp/pi.db` (or a path of your choosing) for
    the backend process, and the reader will follow it.
