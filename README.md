# PI Platform

**Deterministic semantic execution kernel with governance-first architecture.**

[![License](https://img.shields.io/badge/license-Apache%202.0-lightgrey)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](pyproject.toml)
[![Spec](https://img.shields.io/badge/spec-v1.4.0-blue)](docs/PI-RUNTIME-SPEC-v1.4.md)
[![Frontend](https://img.shields.io/badge/console-Next.js%2015-black)](pi-console-frontend/package.json)

> A 4-layer execution platform for structured semantic workloads. No LLM inference in
> the core. No probabilistic decision-making in execution paths. Every operation is
> replay-safe, audit-first, and tenant-isolated.

---

## What This Is

PI Platform routes natural-language intent through a deterministic kernel of
specialized micro-agents (~296 of them). Each agent is a pure function with a
typed Pydantic input / output, runs under a perturbation-based consensus engine,
emits a hash-chained execution receipt, and is replay-safe across versions.

The architecture is formalized in the [PI Runtime Specification v1.4](docs/PI-RUNTIME-SPEC-v1.4.md).

**Core properties**

| | |
|---|---|
| **Fail-closed** | Missing rules, ambiguous policies, and unverified extensions resolve to DENY. |
| **Deterministic execution** | Same inputs → identical outputs. No LLM inference inside the kernel. |
| **Hash-chained audit** | Every receipt links to the previous via SHA-256. Append-only ledger with WAL. |
| **Perturbation consensus** | Each agent runs 3 perturbed copies; 2-of-3 majority gates the verdict. |
| **Tenant-isolated** | Per-tenant DB partitioning, scoped policy engine, quota enforcement. |
| **Capability marketplace** | Audited extensions with explicit trust-zone promotion. |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│  LAYER 4 — PI CONSOLE                                                │
│  FastAPI + Next.js 15. Natural language permitted ONLY here.         │
│  Outputs frozen, SHA-256-hashed ExplicitCompositionRequest.          │
└──────────────────┬───────────────────────────────────────────────────┘
                   ▼  ExplicitCompositionRequest
┌──────────────────────────────────────────────────────────────────────┐
│  LAYER 3 — CAPABILITY ECONOMY                                        │
│  ExtensionManifest lifecycle, policy engine, trust zones, sandbox.   │
│  7-phase catalog admission with deterministic micro-workers.         │
└──────────────────┬───────────────────────────────────────────────────┘
                   ▼  Validated Composition DAG
┌──────────────────────────────────────────────────────────────────────┐
│  LAYER 2 — DETERMINISTIC EXECUTION FABRIC                            │
│  Orchestrator → Router → Chain Engine → Consensus → ~296 agents.     │
│  Append-only ledger, immutable artifact bus, bounded worker mesh,    │
│  scheduler with circuit breakers + chain timeouts.                   │
└──────────────────┬───────────────────────────────────────────────────┘
                   ▼  Execution Receipts + Event Ledger
┌──────────────────────────────────────────────────────────────────────┐
│  LAYER 1 — MULTI-TENANT CONTROL PLANE                                │
│  Tenant registry, quotas, scoped policy, compliance reporting.       │
└──────────────────┬───────────────────────────────────────────────────┘
                   ▼
┌──────────────────────────────────────────────────────────────────────┐
│  FOUNDATION — EVENT FABRIC                                           │
│  Append-only EventBus (cryptographic chaining, ordered partitions).  │
│  Schema evolution with explicit migration DAGs.                      │
│  Cross-version replay engine with compatibility fences.              │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Rust Core (deterministic compute — measured ~5× faster)

The CPU-bound deterministic layer (the micro-agents and the event fabric) is being
ported to a Rust core exposed to Python via PyO3. This is a **verified proof of
architecture**, not yet the full migration — see [`rust/README.md`](rust/README.md)
for the complete writeup. Every claim below is gated by a parity harness.

**Ported & parity-verified (byte-identical to Python, 0 divergences):**
- **205 micro-agents** — across 955+ curated cases and 80k+ differential-fuzz comparisons.
- **Event fabric core** (`pi_event_fabric.bus.core`) — SQLite-backed, SHA-256-chained
  append-only log — identical incl. every event hash and the full chain.
- **Schema-evolution + governance-compiler cores** and the **`pi_agent_chain`
  fail-closed gates** — identical incl. all hashes.

**Measured performance** (`rust/parity/*benchmark*.py`, release build):
- Per agent: **2–12×** faster (compute-heavy regex/entropy/multi-pattern scans).
- **Full agent fan-out at the consensus fabric's real concurrency: ~5×, scaling with
  cores** — the Rust agents release the GIL, which Python's `ThreadPoolExecutor` cannot.

**Opt-in & fail-safe.** Set `PI_USE_RUST_AGENTS=1` and the consensus fabric routes to
the Rust agent where a port exists, falling back to Python on *anything* (flag off,
`pi_core` unbuilt, unported agent, any error). Output parity is proven, so it cannot
change results.

```bash
# Build the Rust core into your venv, then verify
cd rust/crates/pi-py && maturin develop --release        # builds `pi_core`
cargo test --manifest-path ../../Cargo.toml -p pi-agents -p pi-event-fabric   # 792 unit tests
cd ../../parity && python -m pytest -q                   # Rust<->Python agent parity
```

**Findings the harness surfaced** (documented in `rust/README.md`): the
"DeterministicEventBus" actually read wall-clock time (its hashes varied per run —
the Rust port makes the clock injectable); several "deterministic" agents embedded
`datetime.now()` / `list(set())`; and a real `i64`-overflow bug. Honest scope:
~2× of agent files are broken Python in the current tree; the Rust port surfaces
them at compile time.

---

## Quick Start

### Prerequisites

- Python 3.9+
- Node.js 20+ (frontend only)
- Docker 24+ (optional, for compose)

### Local development

```bash
git clone https://github.com/New1Direction/pi-platform.git
cd pi-platform

# 1. Configure secrets
cp .env.example .env
# Generate values:
echo "PI_SECRET_JWT=$(openssl rand -hex 32)" >> .env
echo "PI_SECRET_REQUEST_SIGNING=$(openssl rand -hex 32)" >> .env

# 2. Backend
python -m venv venv && source venv/bin/activate
make dev                 # pip install -e ".[dev,all]"
make test                # full test suite

# 3. Run API
make console-dev         # uvicorn src.pi_console.main:app --reload --port 8080

# 4. Run frontend (separate terminal)
cd pi-console-frontend
npm install
npm run dev              # → http://localhost:3000
```

### Docker Compose

```bash
# Required: secrets must be set or compose refuses to start
export PI_SECRET_JWT=$(openssl rand -hex 32)
export PI_SECRET_REQUEST_SIGNING=$(openssl rand -hex 32)

docker compose -f docker/docker-compose.yml up --build
# Core API:   http://localhost:8000/v1/
# Frontend:   http://localhost:3000
# Metrics:    --profile metrics (Prometheus on :9090)
```

---

## Configuration

All runtime config flows through environment variables. See
[`.env.example`](.env.example) for the full set.

| Var | Required | Default | Purpose |
|---|---|---|---|
| `PI_SECRET_JWT` | ✅ prod | — | HMAC secret for JWT signing |
| `PI_SECRET_REQUEST_SIGNING` | ✅ prod | — | HMAC secret for request anti-replay |
| `PI_STORAGE_PATH` | | `/data/pi_production.db` | Append-only state ledger |
| `PI_LEDGER_DB_PATH` | | `pi_audit_ledger.db` | Audit ledger |
| `PI_MEMORY_PATH` | | `~/.pi_platform/memory.db` | Cross-chain memory store |
| `PI_LLM_GATEWAY_URL` | | — | Optional LLM gateway (simulation mode if unset) |
| `FREE_LLM_API_KEY` | | — | API key for LLM gateway |
| `PI_TARGET_LLM_URL` | | `https://api.openai.com/v1/chat/completions` | Interceptor upstream |
| `PI_SLACK_WEBHOOK_URL` | | — | Audit alerts (must be `https://hooks.slack.com/*`) |
| `PI_ORCHESTRATOR_STRICT_MODE` | | `true` | Block high-risk chains |
| `PI_ORCHESTRATOR_DEFENSIVE_ONLY` | | `false` | Reject all shell/code-exec payloads |
| `PI_CONSENSUS_TIMEOUT_SECONDS` | | `30` | Per-agent perturbation timeout |
| `PI_CHAIN_EXECUTION_TIMEOUT_SECONDS` | | `300` | Global chain deadline |
| `PI_MEMORY_MAX_ROWS` | | `10000` | FTS5 memory size cap |

---

## Repository Layout

```
pi-platform/
├── src/
│   ├── pi_console/               # Layer 4 — FastAPI proxy, 10 routers, middleware
│   ├── pi_extension_governor/    # Layer 3 — Manifests, policy, trust zones
│   ├── pi_interoperability_layer/# Layer 2 — Execution fabric, mesh, receipts
│   ├── pi_micro_agents/          # Layer 2 — ~296 deterministic agents + orchestrator/
│   │   └── orchestrator/         #   Chain engine, consensus, scheduler, memory,
│   │                             #   checkpoint, recovery (circuit breaker), router,
│   │                             #   shield, planner, replay, stream bus, telemetry
│   ├── pi_agent_chain/           # Layer 2 — Semantic reconstruction + ledger
│   ├── pi_agent_interceptor/     # Layer 2 — LLM/command proxy with AST + approval gate
│   ├── pi_event_fabric/          # Foundation — Append-only event bus
│   ├── pi_audit_ledger/          # Foundation — Hash-chained audit trail
│   ├── pi_connector_fabric/      # Layer 1–2 — 7 governed connectors (K8s, TF, OTel…)
│   ├── pi_runtime/               # Browser/clients/skills runtime + ledger orchestrator
│   ├── pi_semantic_diff/         # Differential analysis
│   ├── pi_semantic_validator/    # Schema validation
│   ├── pi_semantic_radius/       # Blast-radius analysis
│   └── pi_production/            # Production hardening: auth, storage, telemetry
├── rust/                          # Rust core (PyO3): agent + event-fabric ports — ~5× faster, parity-verified
│   ├── crates/pi-agents/         #   205 deterministic agents ported to Rust
│   ├── crates/pi-event-fabric/   #   SQLite-backed, SHA-256-chained event bus + schema/governance cores
│   ├── crates/pi-py/             #   PyO3 bindings -> `import pi_core`
│   └── parity/                   #   Rust<->Python equivalence harnesses + benchmarks
├── pi-console-frontend/          # Next.js 15 + React 19 + React Flow dashboard
├── tests/                        # 113+ test modules: unit / integration / conformance / console
├── docker/                       # Compose, Dockerfiles, K8s manifests, Prometheus config
├── docs/
│   ├── PI-RUNTIME-SPEC-v1.4.md   # Current spec (authoritative)
│   ├── PI-RUNTIME-SPEC-v1.{0..3}.md
│   ├── architecture/             # Per-component design docs
│   └── api-reference.md
├── .github/workflows/            # CI: tests, lint, semantic-governance
├── Makefile                      # make help — full target list
├── pyproject.toml                # All deps + extras: needle, all, dev, console
├── .env.example                  # All env vars documented
├── SECURITY.md                   # Reporting policy
└── CONTRIBUTING.md               # Dev setup, commit conventions
```

---

## Key Concepts

### `ExplicitCompositionRequest`

The sole cross-layer contract. A frozen, SHA-256-fingerprinted Pydantic model.

```python
class ExplicitCompositionRequest(BaseModel):
    request_id: str
    tenant_id: str
    console_session_id: str
    nodes: List[CompositionNode]       # DAG
    edges: List[CompositionEdge]
    global_bounds: Dict[str, int]      # max_nodes, max_depth, max_fanout
    simulation_only: bool
    approved_by_user: bool
    strict: bool = True
    request_hash: str                  # H(canonical_json(payload))
    model_config = {"frozen": True}
```

### Perturbation Consensus

Every agent invocation runs 3 independent perturbed copies under a
`ThreadPoolExecutor`, with `PI_CONSENSUS_TIMEOUT_SECONDS` enforced via
`future.result(timeout=…)`. A `PiConsensusBreaker` detects divergence;
the chain fails closed unless 2-of-3 produce the same verdict.

### Receipt Chain

Every worker execution emits an `ExecutionTrace`, hash-chained to the previous
trace. Phase boundaries form an independent chain. Together they create an
immutable, tamper-evident record.

### Trust Zones

| Zone | Governance |
|---|---|
| `CORE_TRUSTED` | Explicit allowlist only |
| `GOVERNED_EXTENSION` | Policy + sandbox enforced |
| `SANDBOX_EXPERIMENTAL` | Isolated; never promotable |

### Deterministic Scheduling

Workers map to shards via `SHA-256(worker_id)[:8] mod shard_count`. Same
worker + same shard count = same assignment, every time, on every machine.

### Resilience Primitives

- **Circuit breaker** (`orchestrator/recovery.py`) — per-step closed/open/half-open
  states; opens after N consecutive failures with cool-off, preventing
  thundering-herd retries against a sick downstream.
- **Checkpoint goal-hash** (`orchestrator/checkpoint.py`) — every checkpoint
  carries a SHA-256 of its goal; `load(chain_id, current_goal=…)` raises
  `CheckpointGoalMismatch` if a chain is resumed under a different prompt.
- **Bounded memory** (`orchestrator/memory.py`) — FTS5-backed cross-chain store
  with a row cap and periodic VACUUM (prevents unbounded growth).
- **Chain deadlines** (`orchestrator/chain_engine.py`) — global
  `PI_CHAIN_EXECUTION_TIMEOUT_SECONDS` enforced between every step.

---

## Testing

```bash
make test              # all suites
make test-core         # unit
make test-conformance  # PI Runtime Spec conformance
make test-console      # boundary tests for Layer 4
make coverage          # coverage report (60% gate)
make coverage-html     # → htmlcov/index.html
```

| Suite | Location | Scope |
|---|---|---|
| Unit | `tests/unit/` | Per-module |
| Integration | `tests/integration/` | Cross-runtime |
| Conformance | `tests/conformance/` | PI Runtime Spec rules |
| Console | `tests/console/` | Boundary enforcement |

---

## Production Deployment

### Docker Compose

`docker/docker-compose.yml` refuses to start if `PI_SECRET_JWT` and
`PI_SECRET_REQUEST_SIGNING` are unset (`:?` required-variable syntax).

### Kubernetes

```bash
# 1. Create secrets first — manifest no longer ships placeholder values
kubectl create secret generic pi-secrets \
  --from-literal=jwt-secret=$(openssl rand -hex 32) \
  --from-literal=request-signing-secret=$(openssl rand -hex 32)

# 2. Apply
kubectl apply -f docker/k8s-deployment.yaml
```

### API Auth

Every request requires:

```
Authorization: Bearer <jwt_token>
X-Tenant-ID:   <tenant_id>
X-Correlation-ID: <trace_id>   (optional)
```

```bash
curl -H "Authorization: Bearer $TOKEN" \
     -H "X-Tenant-ID: tenant_001" \
     http://localhost:8000/v1/health
```

### Production posture

| Feature | Status |
|---|---|
| Append-only SQLite (WAL, hash-chained) | ✅ |
| JWT auth (HMAC-SHA256) | ✅ |
| Request signing, 300s anti-replay window | ✅ |
| RBAC (admin/operator/viewer/api_key) | ✅ |
| Per-tenant sliding-window rate limiting | ✅ |
| Hash-chained audit logging | ✅ |
| Prometheus metrics + JSON structured logs | ✅ |
| Health / readiness probes | ✅ |
| Non-root container user | ✅ |
| Tenant isolation at DB level | ✅ |
| Append-only triggers (UPDATE/DELETE blocked) | ✅ |
| Security headers on console (CSP, X-Frame-Options, …) | ✅ |
| SSRF-validated webhook egress | ✅ |
| `random.uuid4()` for sensitive IDs (no `hash()`) | ✅ |
| AST-based command-safety inspection | ✅ |
| Word-boundary keyword router | ✅ |
| JWT weakness monitor (alg=none, missing exp/aud) | ✅ |

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

The codebase has been through multiple audit + hardening passes. Notable
fixes shipped:

- Consensus deadlock prevention via `future.result(timeout=…)` and None-verdict guards
- Backpressure scheduler now returns `success=False` (no phantom approvals)
- Webhook egress restricted to `https://hooks.slack.com/*`
- AST inspector extended for `compile()`, `os.popen`, `subprocess(shell=True)`
- Shell-chaining patterns (`;`, `&&`, `||`, `` ` ``, `$(`) floor risk score at 60
- SHA-256 throughout (no MD5 trace IDs)
- File-handle lifetimes use `with open(...)` blocks
- Frontend errors sanitize server stack traces; `URLSearchParams` for safe URLs
- `JSON.parse` wrapped in IIFE try/catch in replay viewer
- `.gitignore` covers `*.db`, `*.gguf`, `*.safetensors`, model weights
- Path-traversal guard on ledger target IDs (`^[A-Za-z0-9_-]{1,64}$`)

Open audit items are tracked in the issue queue. PRs welcome.

---

## Governance Philosophy

> **Semantic cognition assists infrastructure — it does not replace it.**

- Specialization scales better than autonomy. The platform evolves horizontally:
  more workers, tighter contracts, stronger provenance, stricter governance.
- No LLM inference in the core. Natural language enters at Layer 4 and is
  translated into strict JSON before crossing the boundary.
- Deterministic execution. The kernel behaves like a compiler pipeline or OS
  scheduler — not an autonomous agent swarm.
- Fail-closed everywhere. Missing rules, ambiguous policies, and unverified
  extensions all resolve to DENY.

---

## License

[Apache License 2.0](LICENSE)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, commit conventions,
and governance principles.

---

## Acknowledgments

Built with [Pydantic v2](https://docs.pydantic.dev/),
[FastAPI](https://fastapi.tiangolo.com/),
[Next.js](https://nextjs.org/),
[React Flow](https://reactflow.dev/), and
[shadcn/ui](https://ui.shadcn.com/).
