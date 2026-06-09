# Agentdex

<div class="pi-eyebrow">Was: Agents / Registry</div>

The **Agentdex** is a live browser over all 248 registered micro-agents — sourced from
`POST /api/v1/capabilities/list` — rendered as collectible creatures. Every agent has a
**Type**, flavor **stats**, and a procedural sprite, so you read a roster the way you'd
read a team.

## Types

Each agent is classified by name + keywords into one of ten Types (plus a Generalist
fallback). The Type drives the creature's color everywhere it appears:

<div class="pi-chips">
  <span class="pi-chip" style="color:var(--t-contract)">🔮 Smart-Contract</span>
  <span class="pi-chip" style="color:var(--t-zk)">🧮 Crypto / ZK</span>
  <span class="pi-chip" style="color:var(--t-ai)">🧠 AI / LLM</span>
  <span class="pi-chip" style="color:var(--t-secrets)">🔑 Secrets</span>
  <span class="pi-chip" style="color:var(--t-web)">🌐 Web / API</span>
  <span class="pi-chip" style="color:var(--t-infra)">🐳 Infra</span>
  <span class="pi-chip" style="color:var(--t-supply)">📦 Supply-Chain</span>
  <span class="pi-chip" style="color:var(--t-privacy)">🛡️ Privacy</span>
  <span class="pi-chip" style="color:var(--t-quality)">🔧 Code-Quality</span>
  <span class="pi-chip" style="color:var(--t-runtime)">⚙️ Runtime</span>
</div>

The **Type and creature** are seeded from the agent's name — a deterministic
recognizability layer (the same agent looks identical everywhere; drop in real sprites
later and the seeding stays).

The **stats are real**, aggregated live from the [Battle Log](ledger.md):

- **Runs** — how many times this agent has actually executed.
- **Find rate** — share of its runs that surfaced real risk (≥50) or an anomaly.
- **Avg risk** — mean risk score it has returned.
- **Reliability** — share of runs that completed without failure.
- **⚠ Routing ambiguity** — a structural flag: when an agent shares a keyword with
  others, routing by that keyword may land elsewhere. Derived from the registry, not the
  ledger.

Agents that haven't run yet read **"no ledger runs yet"** — truth over flavor; a fresh
ledger genuinely has nothing to show.

!!! note "Recorded now: terrain (an interpretation). Not shown yet: concentration"
    Each run now records its **terrain** — the content-class a classifier *infers* for
    the input, stamped with provenance (`{class, by, at}`). It is an **interpretation,
    not a property of the input**: a different classifier could assign a different class,
    so it lives in the fallible interpretation layer, never as ground truth, and never
    conditions the gate.

    What's still **not** shown is **concentration**: a *specialist* (fires on one terrain)
    and a *generalist* (fires everywhere) can share a find-rate — the difference is
    concentration across terrain. That needs enough terrain-tagged history to accrue
    first; computing it on today's thin data would be fiction. It's the next step toward
    the Migration Map, not this slice.

## What a capability looks like

Each registered route surfaces as a `MarketplaceCapability`:

```json
{
  "capability_id": "cap_pigitsecscanner",
  "runtime": "pi-extension-governor",
  "operation": "SANDBOX",
  "description": "PiGitSecScanner — keywords: scan requirements, dependency scan, …",
  "schema_version": "1.0.0",
  "trust_tier": "GOVERNED",
  "compatibility_tags": ["scan requirements", "dependency scan", "git scan", "…"],
  "deterministic_bounds": { "max_depth": 1, "max_fanout": 1 }
}
```

- **`capability_id`** — `cap_<agentname lowercased>`.
- **`description`** — `"<AgentName> — keywords: …"`; the UI parses the name on ` — `.
- **`compatibility_tags`** — the router keywords; these are what the [Party](builder.md)
  dispatches on, and what classifies the agent's Type.
- **`trust_tier`** — see the [trust-tier lifecycle](../architecture/trust-tiers.md).
  Registered platform agents are `GOVERNED`.

## Filtering

Filter by **Type** or trust tier (`GOVERNED`, `AUDITED`, `VERIFIED`, `UNVERIFIED`), or
search by name, runtime, or tag. The dex counter shows `matched / total`. If the backend
is unreachable the grid shows an explicit error and a **Retry** button — never a silent
empty state.

## The agent pattern

Every micro-agent is a single self-contained module following the same shape:

```python
def is_strict_mode() -> bool: ...            # resolve_strict_mode("PI_<NAME>_STRICT_MODE")
def detect_<x>_anomalies(content) -> tuple[float, list[str]]: ...
class <Name>Input(BaseModel): ...
class <Name>Output(BaseModel):               # is_secure, risk_score, status, flagged_*
    ...
class <Name>:                                # primary scan method
    ...
AgentRouter.register(agent_name=..., keywords=[...], agent_class=..., input_factory=...)
```

New agents that follow this pattern can be generated in the [Forge](forge.md).
