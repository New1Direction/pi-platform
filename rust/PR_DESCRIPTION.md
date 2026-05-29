# Rust core — proof of architecture (Python → Rust via PyO3)

A verified proof that the PI Platform's deterministic core ports to Rust behind
PyO3, gated by behavioral-equivalence harnesses. **Not the full migration** — the
de-risking milestone, with parity as the gate (not "it compiles"). All new code
lives under `rust/`; no pre-existing files are modified.

## What's verified

| Area | Coverage | Gate |
|------|----------|------|
| **Micro-agents** | **205** ported (the entire clean self-contained pool) | 615 unit tests + 2,145 curated parity + 82k general fuzz + 8.5k structured fuzz — **0 divergences** |
| **Event bus** (`pi_event_fabric.bus.core`) | full: SQLite-backed, SHA-256-chained append-only log, reads, checkpoints, replay | curated parity + 2k+ randomized fuzz (incl. floats) — byte-identical incl. every hash |
| **Schema evolution** (core) | fingerprint, compatibility diff/validate, migration BFS + data migration | full parity incl. SHA-256 fingerprints |
| **Governance compiler** (core) | rule/compiled hashing, operator evaluator, fail-closed priority engine | full parity incl. decision hashes |
| **Governance kernel gates** (`pi_agent_chain`) | SchemaGate + TransitionGate (fail-closed) | full parity (rule/severity/context/action) |

Totals: **792 Rust unit tests**, five parity harnesses, all byte-identical to the
Python originals (deterministic under forced 16-thread test parallelism).

## Architecture

```
Rust core (pi-agents, pi-event-fabric)  ──maturin/PyO3──▶  pi_core  ◀── Python glue
```
`canonical.rs` reproduces CPython `json.dumps(sort_keys, ensure_ascii, compact)`
incl. float repr — the hashing linchpin. Storage uses real SQLite via `rusqlite`.

## Findings the harness surfaced (not visible by reading the code)

- **The "DeterministicEventBus" is not deterministic** — its clock reads wall-clock
  time; identical inputs hash differently per run (its `sequence_counter` is also
  frozen). The Rust port makes the clock injectable → genuinely deterministic.
- **Non-deterministic "deterministic" agents**: `threat_model` (`list(set())` order),
  `niche_scraper` (`datetime.now()`), gate `violation_id`/`detected_at`.
- **A real port bug** (i64 overflow on huge Redis ports) caught by a compiler warning.
- **51 of 299 micro-agent files are broken Python** (SyntaxError) in the current product.
- Python `str`-Enum `f"{member}"` renders as `ClassName.NAME` on 3.9 (caught + matched).

## Explicitly out of scope (follow-on)

- ~34 non-clean agents (AST-based → need `rustpython-parser`; FastAPI/network → stay Python).
- Event-fabric `ordering/shard`, `bus/semantic_fabric`, `replay/cross_version`.
- Governance kernel beyond the gates: `hooks`, entropy monitor, `kernel` orchestration,
  `pipeline`, `models`, `ledger`, `verification/*`.
- SQLite registry CRUD layers (non-deterministic `datetime('now')` timestamps).

## How to verify

```bash
cd rust && cargo test                      # 792 unit tests
uv venv .venv-poc --python 3.11 && uv pip install --python .venv-poc pydantic pytest maturin
source .venv-poc/bin/activate
cd rust/crates/pi-py && maturin develop
cd ../../parity && python -m pytest -q     # agent parity
PYTHONPATH=.:../../src python event_fabric_parity.py
PYTHONPATH=.:../../src python schema_governance_parity.py
PYTHONPATH=.:../../src python governance_gates_parity.py
```

🤖 Generated with [Claude Code](https://claude.com/claude-code)
