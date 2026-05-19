# PI Platform

## Deterministic Semantic Execution Kernel

[![Tests](https://img.shields.io/badge/tests-520%2F520%20passing-brightgreen)](#testing)
[![Spec](https://img.shields.io/badge/spec-v1.2.0-blue)](docs/PI-RUNTIME-SPEC-v1.1.md)
[![License](https://img.shields.io/badge/license-Apache%202.0-lightgrey)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](pyproject.toml)

> **A governance-first, deterministic execution platform for structured semantic workloads. No LLM inference in the core. No probabilistic decision-making in execution paths. Every operation is replay-safe, audit-first, and tenant-isolated.**

---

## What is PI Platform?

PI Platform is a **4-layer deterministic execution kernel** designed for enterprises and teams that require:

- **Immutable audit trails** — Every operation is receipted, chained, and replayable
- **Deterministic scheduling** — Same inputs always produce identical outputs
- **Fail-closed governance** — Policy ambiguity resolves to DENY, never ALLOW
- **Multi-tenant isolation** — Absolute boundary enforcement between tenants
- **Capability marketplace** — Audited extensions with trust-zone enforcement

The architecture is formalized in the [PI Runtime Specification v1.0](docs/PI-RUNTIME-SPEC-v1.0.md), which serves as the single source of truth for all runtime behavior.

---

## Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│  LAYER 4: PI CONSOLE                                                  │
│  Human interface boundary. Natural language permitted ONLY here.      │
│  Outputs: ExplicitCompositionRequest JSON (frozen, SHA-256 hashed)    │
└──────────────────┬────────────────────────────────────────────────────┘
                   │ ExplicitCompositionRequest
┌──────────────────▼────────────────────────────────────────────────────┐
│  LAYER 3: CAPABILITY ECONOMY / MARKETPLACE                            │
│  ExtensionManifest lifecycle, policy engine, trust zones, sandbox     │
│  7-phase catalog admission pipeline with deterministic micro-workers  │
└──────────────────┬────────────────────────────────────────────────────┘
                   │ Validated Composition DAG
┌──────────────────▼────────────────────────────────────────────────────┐
│  LAYER 2: SHARD-COORDINATED DETERMINISTIC EXECUTION FABRIC            │
│  Central Orchestrator Kernel, 7-phase fixed pipeline (INGEST→EMIT)    │
│  Artifact Bus (immutable slots), Worker Mesh (bounded, deterministic) │
│  Replay Ledger (append-only, hash-chained), Shard Coordinator         │
└──────────────────┬────────────────────────────────────────────────────┘
                   │ Execution Receipts + Event Ledger
┌──────────────────▼────────────────────────────────────────────────────┐
│  LAYER 1: MULTI-TENANT CONTROL PLANE                                  │
│  Tenant registry with quota enforcement, scoped policy engine         │
│  Execution log, compliance reporting, tenant-scoped audit trail       │
└───────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- Python 3.9+
- Node.js 20+ (for console frontend)
- Docker (optional)

### One-Command Setup

```bash
git clone https://github.com/New1Direction/pi-platform.git
cd pi-platform
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
make dev
make test
```

### Running the Console

```bash
# Terminal 1 — Backend API
make console-dev          # or: uvicorn src.pi_console.main:app --reload --port 8080

# Terminal 2 — Frontend (requires Node 20+)
cd pi-console-frontend
npm install
npm run dev               # → http://localhost:3000
```

### Docker Compose

```bash
docker compose -f docker/docker-compose.yml up
```

---

## Repository Structure

```
pi-platform/
├── src/
│   ├── pi_agent_chain/              — Layer 2: Semantic reconstruction
│   ├── pi_semantic_diff/            — Layer 2: Differential analysis
│   ├── pi_semantic_validator/       — Layer 2: Schema validation
│   ├── pi_semantic_radius/          — Layer 2: Blast radius
│   ├── pi_interoperability_layer/   — Layer 1–2: Execution fabric, mesh, receipts
│   ├── pi_extension_governor/       — Layer 3: Manifests, policy, trust zones
│   └── pi_console/                  — Layer 4: FastAPI proxy + boundary schemas
├── pi-console-frontend/             — Layer 4: Next.js 15 + React Flow dashboard
├── tests/
│   ├── unit/                        — Per-module unit tests
│   ├── integration/                 — Cross-runtime integration tests
│   ├── conformance/                 — PI Runtime Spec conformance (26 tests)
│   └── console/                     — Boundary enforcement tests (17 tests)
├── docs/
│   ├── PI-RUNTIME-SPEC-v1.0.md      — Formal execution kernel specification
│   ├── assets/diagrams.html         — Interactive SVG architecture diagrams
│   ├── architecture/                — Layer-by-layer architecture guides
│   ├── api-reference.md             — OpenAPI tool schemas and examples
│   └── deployment.md                — Docker, local dev, and production setup
├── docker/                          — Dockerfiles and compose definitions
├── scripts/                         — Utility scripts (setup, release checks)
├── .github/workflows/               — CI/CD: test, lint, conformance
├── pyproject.toml                   — Unified package configuration
├── Makefile                         — Common development commands
├── README.md                        — This file
├── LICENSE                          — Apache 2.0
├── CONTRIBUTING.md                  — Contribution guidelines
├── SECURITY.md                      — Security policy and vulnerability reporting
└── CODE_OF_CONDUCT.md               — Community standards
```

---

## PI Runtime Specification

The [PI Runtime Specification v1.0](docs/PI-RUNTIME-SPEC-v1.0.md) is the authoritative reference for:

- Artifact lifecycle state machine (ART-1...ART-5)
- Graph execution semantics (GRAPH-1...GRAPH-3, NODE-1...NODE-3)
- Phase transition guarantees (PHASE-1...PHASE-6)
- Replay invariants (REPLAY-1...REPLAY-4)
- Deterministic scheduling rules (SCHED-1...SCHED-6)
- Policy evaluation order (POLICY-1...POLICY-6)
- Shard synchronization semantics (SHARD-1...SHARD-6)
- Receipt chain model (RECEIPT-1...RECEIPT-4)
- Trust-zone promotion rules (TZ-1...TZ-5)

Every rule maps to a specific file and class in the reference implementation (Section 13 of the spec).

---

## Testing

### Full Platform Test Suite

```bash
make test          # Run all tests (409 passing)
make test-core     # Core runtime tests only
make test-conformance  # Runtime spec conformance (26 tests)
make test-console  # Console boundary tests (17 tests)
```

### Test Breakdown

| Module | Tests | Status |
|--------|-------|--------|
| pi-agent-chain | 78 (+ 2 skipped) | ✅ |
| pi-semantic-diff | 11 | ✅ |
| pi-semantic-validator | 36 | ✅ |
| pi-semantic-radius | 11 | ✅ |
| pi-interoperability-layer | 194 | ✅ |
| pi-extension-governor | 36 | ✅ |
| pi-console boundary | 17 | ✅ |
| pi-runtime-spec conformance | 26 | ✅ |
| **TOTAL** | **409 passing** | ✅ |

---

## Governance Philosophy

> **"Semantic cognition assists infrastructure — does not replace it."**

- **Specialization scales better than autonomy.** The platform evolves horizontally (more workers, tighter contracts, stronger provenance, stricter governance).
- **No LLM inference in core.** Natural language is permitted only in Layer 4 (PI Console), where it is translated into strict JSON before crossing the boundary.
- **Deterministic execution.** The kernel behaves like a compiler pipeline or OS scheduler — not an autonomous agent swarm.
- **Fail-closed everywhere.** Missing rules, ambiguous policies, and unverified extensions all resolve to DENY.

---

## Key Concepts

### ExplicitCompositionRequest

The **sole cross-layer contract**. Every interaction between the human interface and the execution kernel flows through this frozen, SHA-256-fingerprinted Pydantic model:

```python
class ExplicitCompositionRequest(BaseModel):
    request_id: str
    tenant_id: str
    console_session_id: str
    nodes: List[CompositionNode]       # DAG nodes
    edges: List[CompositionEdge]       # DAG edges
    global_bounds: Dict[str, int]      # max_nodes, max_depth, max_fanout, etc.
    simulation_only: bool              # simulate or execute
    approved_by_user: bool             # explicit approval required
    strict: bool = True                # fail-closed
    request_hash: str                  # H(canonical_json(payload))
    model_config = {"frozen": True}
```

### Receipt Chain

Every worker execution produces an `ExecutionReceipt`, chained to the previous receipt via SHA-256. Phase boundaries form an independent chain. Together they create an immutable, tamper-evident record of every operation.

### Trust Zones

| Zone | Level | Governance |
|------|-------|------------|
| `CORE_TRUSTED` | Highest | Explicit allowlist only |
| `GOVERNED_EXTENSION` | Standard | Policy + sandbox enforced |
| `SANDBOX_EXPERIMENTAL` | Isolated | No governance authority, never promotable |

### Deterministic Scheduling

Workers are assigned to shards via `SHA-256(worker_id)[:8] mod shard_count`. Same worker + same shard count = same assignment, every time, on every machine.

---

## Production Deployment

### Quick Start (Docker Compose)

```bash
git clone https://github.com/New1Direction/pi-platform.git
cd pi-platform

# Set production secrets
export PI_SECRET_JWT=$(openssl rand -hex 32)
export PI_SECRET_REQUEST_SIGNING=$(openssl rand -hex 32)

docker-compose -f docker/docker-compose.yml up --build
```

The API will be available at `http://localhost:8000/v1/`. Health check at `/v1/health/ready`.

### Kubernetes

```bash
kubectl apply -f docker/k8s-deployment.yaml
kubectl create secret generic pi-secrets \
  --from-literal=jwt-secret=$(openssl rand -hex 32) \
  --from-literal=request-signing-secret=$(openssl rand -hex 32)
```

### API Authentication

Every request requires:
- `Authorization: Bearer <jwt_token>`
- `X-Tenant-ID: <tenant_id>`
- Optional: `X-Correlation-ID: <trace_id>`

Example:
```bash
curl -H "Authorization: Bearer $TOKEN" \
     -H "X-Tenant-ID: tenant_001" \
     -H "Content-Type: application/json" \
     http://localhost:8000/v1/health
```

### Production Features

| Feature | Status |
|---------|--------|
| Persistent SQLite append-only storage | ✅ WAL mode, hash-chained |
| JWT authentication | ✅ HMAC-SHA256, deterministic claims |
| Request signing (anti-replay) | ✅ HMAC-SHA256, 300s tolerance |
| RBAC (admin/operator/viewer/api_key) | ✅ Hardcoded, deterministic |
| Rate limiting (sliding window) | ✅ Per-tenant + per-actor |
| Audit logging (hash-chained) | ✅ Every API action |
| Prometheus metrics | ✅ Counter / Gauge / Histogram |
| Structured logging (JSON) | ✅ Correlation ID propagation |
| Distributed tracing (custom) | ✅ Immutable spans |
| Health / readiness probes | ✅ 200 healthy / 503 degraded |
| Docker multi-stage build | ✅ Non-root user |
| Kubernetes manifests | ✅ Deployment + PVC + Secret |
| Append-only DB triggers | ✅ UPDATE/DELETE blocked |
| Tenant isolation (DB level) | ✅ Composite indexes |
| Backup (single-file SQLite) | ✅ WAL checkpoint + copy |

### Security Model

- **Fail-closed:** Every new endpoint defaults to deny
- **Immutable history:** Snapshots, receipts, and audit logs cannot be modified
- **Deterministic auth:** No probabilistic session generation
- **Least privilege:** Container runs as non-root `piuser`
- **Secret rotation:** `SecretManager.rotate_secret()` generates cryptographically safe values

### Monitoring Stack

Enable Prometheus metrics sidecar:
```bash
docker-compose -f docker/docker-compose.yml --profile metrics up
```

Metrics endpoint: `http://localhost:8000/v1/metrics` (Prometheus format)

## License

[Apache License 2.0](LICENSE)

---

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting and the security checklist.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, commit conventions, and governance principles.

---

## Acknowledgments

Built with:
- [Pydantic v2](https://docs.pydantic.dev/) — Frozen models, schema validation
- [FastAPI](https://fastapi.tiangolo.com/) — Console proxy layer
- [React Flow](https://reactflow.dev/) — DAG visual builder
- [Next.js](https://nextjs.org/) — Console frontend
- [shadcn/ui](https://ui.shadcn.com/) — Console UI components
