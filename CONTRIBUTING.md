# Contributing to PI Platform

Thank you for your interest in PI Platform. This is a deterministic semantic execution kernel with strict governance boundaries. Please read this guide before proposing changes.

## Governance Principles

- **Determinism first** — Any change to Layers 1–3 must preserve bit-for-bit replay safety
- **Fail-closed** — New policy rules or enforcement points must default to DENY
- **Boundary integrity** — The `ExplicitCompositionRequest` contract between Layer 4 and Layers 1–3 is immutable
- **Tenant isolation** — No cross-tenant leakage can ever be introduced

## Development Setup

```bash
git clone https://github.com/New1Direction/pi-platform.git
cd pi-platform
python -m venv venv
source venv/bin/activate
make dev
make test
```

## Repository Layout

```
src/
  pi_agent_chain/          — Semantic reconstruction pipeline
  pi_semantic_diff/        — Differential semantic analysis
  pi_semantic_validator/   — Schema and contract validation
  pi_semantic_radius/      — Blast radius computation
  pi_interoperability_layer/ — Execution fabric, shard coordination, mesh, receipts
  pi_extension_governor/   — Manifest system, policy engine, trust zones, sandbox
  pi_console/              — Human interface boundary (FastAPI proxy + schemas)
pi-console-frontend/       — Next.js 15 frontend (React Flow, shadcn/ui)
tests/
  unit/                    — Per-module unit tests
  integration/             — Cross-runtime integration tests
  conformance/             — PI Runtime Specification conformance suite
  console/                 — Boundary enforcement tests
docs/
  PI-RUNTIME-SPEC-v1.0.md  — Formal execution kernel specification
  architecture/            — Architecture diagrams and layer docs
  deployment.md            — Docker and deployment guide
  api-reference.md         — OpenAPI tool schemas and examples
```

## How to Contribute

1. **Check the runtime spec** — Does your change align with PI-RUNTIME-SPEC-v1.0.md?
2. **Open an issue first** — For non-trivial changes, open an issue describing the problem and proposed approach
3. **Make atomic commits** — Each commit should be a single logical change with a clear message
4. **Add/update tests** — Every behavioral change must include a test. Conformance tests for spec-affecting changes
5. **Run the full suite** — `make test` must pass (409+ tests)
6. **Sign your commits** — Prefer GPG-signed commits

## Commit Message Format

```
TYPE(scope): brief description

Body: explain the what and why, referencing spec sections where applicable

Refs: #issue-number
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`

## Code Style

- Python: ruff + mypy (strict mode)
- TypeScript: strict compiler, Tailwind + shadcn/ui conventions
- All Pydantic models: `frozen=True` unless explicitly documented otherwise
- All hashes: canonical JSON + SHA-256

## Security

See [SECURITY.md](SECURITY.md). Any change affecting trust zones, policy evaluation, tenant isolation, or sandbox boundaries requires a security review.

## Questions?

Open a Discussion for architecture questions. Open an Issue for bugs or feature requests.
