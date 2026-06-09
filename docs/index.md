<div class="pi-hero">
  <div class="pi-eyebrow">Deterministic · Governed · Replay-safe</div>
  <h1 class="pi-hero__title">The kernel that<br><span class="pi-grad">never guesses.</span></h1>
  <p class="pi-hero__lede">
    PI Platform routes natural-language intent through a deterministic core of
    248 specialized security micro-agents. LLMs may <em>propose</em> — the kernel
    decides, in pure functions, and hash-chains every receipt.
  </p>
  <div class="pi-hero__cta">
    <a class="md-button md-button--primary" href="getting-started/">Boot it locally →</a>
    <a class="md-button" href="console/">Tour the console</a>
    <a class="md-button" href="console/compass/">Governance Compass</a>
  </div>
  <div class="pi-strip">
    <span><span class="dot">◆</span> <b>248</b> micro-agents</span>
    <span><span class="dot">◆</span> <b>1</b> sandboxed runtime</span>
    <span><span class="dot">◆</span> <b>0</b> probabilistic decisions in core</span>
    <span><span class="dot">◆</span> same input → same <b>receipt</b></span>
  </div>
</div>

PI Platform is a **deterministic semantic execution kernel with a governance-first
architecture**. Every agent is a pure function with typed Pydantic input/output, runs
under a perturbation-based consensus engine, and every execution is hash-chained into
a replay-safe audit ledger.

!!! note "No probabilistic execution in the core"
    LLMs may *propose* work, but the kernel never makes probabilistic decisions on an
    execution path. Routing is keyword-deterministic, agents are pure, and the ledger
    is content-addressed — **the same input always produces the same receipt.**

## The four layers

| Layer | Responsibility |
|-------|----------------|
| **L4 — Human Interface** | The desktop console + HTTP API. The *only* way in is an `ExplicitCompositionRequest`. |
| **L3 — Orchestration** | Keyword router → micro-agent dispatch → consensus engine. |
| **L2 — Agents** | 248 registered micro-agents, each a typed pure function under `pi-extension-governor` / `SANDBOX`. |
| **L1 — Ledger** | Hash-chained `execution_trace` store + deterministic replay. |

## Explore the console

The desktop console (`pi-tauri/`) wraps all of this in a Windows-98 shell with a
Pokémon-style **Agentdex** game layer — every agent gets a Type, stats, and a
procedural creature, so picking a security team feels like building a party.

<div class="grid cards" markdown>

-   :material-pokeball: **Agentdex**

    ---

    Browse all 248 micro-agents as collectible creatures — filtered by Type, trust
    tier, and capability. [Open the dex →](console/agents.md)

-   :material-account-group: **Party** *(Builder)*

    ---

    Pick a team, drop in a file, **Simulate** then **Run** — each agent dispatched by
    keyword under sandbox governance. [Build a party →](console/builder.md)

-   :material-sword-cross: **Battle Log** *(Ledger)*

    ---

    Every scan lands here as a hash-chained trace with risk score, routed agent, and
    replayable integrity. [Read the log →](console/ledger.md)

-   :material-anvil: **Agent Forge**

    ---

    AI-assisted micro-agent generator behind a static-audit gate — drafts land
    quarantined as `UNVERIFIED`. [Forge an agent →](console/forge.md)

</div>

## Governance as navigation

The console's **Governance Compass** reframes safety as a *heading* rather than a
gate. Behind a single Gate⇄Compass switch, it reads the orchestrator's own signals,
the file in front of you, and what past runs learned — and lets the route **emerge**.

<div class="pi-chips">
  <span class="pi-chip accent">① Compass — which way is north</span>
  <span class="pi-chip accent">② Navigate — the route emerges</span>
  <span class="pi-chip accent">③ Instincts — the field learns</span>
  <span class="pi-chip accent">④ Live — it adapts as it runs</span>
</div>

It is a **lens**: it changes what you see and the *suggested* order — never what the
gate, sandbox, and ledger enforce. [Read the Compass guide →](console/compass.md)

## Two front-ends

- **Desktop console** (`pi-tauri/`) — a Tauri 2 + React 19 + Vite app; the primary
  interface documented here.
- **Web console** (`pi-console-frontend/`) — a Next.js 15 dashboard on the same backend.

Both speak to the FastAPI backend (`pi_console.main:app`) over the same
[`/api/v1`](api-reference.md) surface.

<hr class="pi-rule">

**Next:** [Getting Started](getting-started.md) · [Desktop Console](console/index.md) ·
[Architecture](architecture/orchestrator-routing.md)
