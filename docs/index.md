# PI Platform

**A deterministic semantic execution kernel with governance-first architecture.**

PI Platform routes natural-language intent through a deterministic kernel of
specialized security micro-agents. Each agent is a pure function with typed
Pydantic input/output, runs under a perturbation-based consensus engine, and
every execution is hash-chained into a replay-safe audit ledger.

!!! note "No probabilistic execution in the core"
    LLMs may *propose* work, but the kernel never makes probabilistic decisions
    on an execution path. Routing is keyword-deterministic, agents are pure, and
    the ledger is content-addressed — the same input always produces the same
    receipt.

## The four layers

| Layer | Responsibility |
|-------|----------------|
| **L4 — Human Interface** | The desktop console + HTTP API. The *only* way in is an `ExplicitCompositionRequest`. |
| **L3 — Orchestration** | Keyword router → micro-agent dispatch → consensus engine. |
| **L2 — Agents** | 248 registered micro-agents, each a typed pure function under `pi-extension-governor` / `SANDBOX`. |
| **L1 — Ledger** | Hash-chained `execution_trace` store + deterministic replay. |

## What you can do

<div class="grid cards" markdown>

-   :material-cube-outline: **Build pipelines**

    Compose micro-agents into a DAG in the [Builder](console/builder.md), simulate,
    then execute under sandbox governance.

-   :material-grid: **Browse 248 agents**

    Search the live [Agent Registry](console/agents.md) by capability, keyword, or
    trust tier.

-   :material-anvil: **Generate new agents**

    Use the AI-assisted [Agent Forge](console/forge.md) to draft new micro-agents
    that follow the platform pattern — audited before they're ever wired in.

-   :material-file-tree: **Audit everything**

    Every execution is hash-chained into the [Ledger](console/ledger.md) with risk
    scores, routed agent, and replayable integrity verification.

</div>

## Two front-ends

- **Desktop console** (`pi-tauri/`) — a Tauri 2 + React 19 + Vite app, the primary
  interface documented here.
- **Web console** (`pi-console-frontend/`) — a Next.js 15 dashboard that talks to the
  same backend.

Both speak to the FastAPI backend (`pi_console.main:app`) over the same
[`/api/v1`](api-reference.md) surface.

## Next steps

- [Getting Started](getting-started.md) — boot the backend + console locally.
- [Desktop Console](console/index.md) — a tour of all six tabs.
- [Architecture](architecture/orchestrator-routing.md) — how routing, trust tiers, and the ledger work.
