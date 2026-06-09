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

Stats are flavor (it's a game) but **deterministic** — a given agent always renders the
same Type, stats, and creature, because everything is seeded from its name. That's a
recognizability layer, not random art: drop in real sprites later and the seeding stays.

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
