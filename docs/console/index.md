# Desktop Console

<div class="pi-eyebrow">pi-tauri · Tauri 2 + React 19 + Vite</div>

The desktop console is the primary way into the platform — a deliberate **Windows 98**
shell wrapped around a **Pokémon-style game layer**. The retro chrome isn't a gimmick:
it makes a 248-agent security kernel legible to people who never wrote a DAG. You pick a
*party*, drop in a file, and run — every action still lands in the same hash-chained
ledger underneath.

It talks to the FastAPI backend over [`/api/v1`](../api-reference.md).

## Layout

The shell is a Win98 desktop: each surface is a folder icon on the teal wallpaper that
opens its window. A PC-stats widget and connection indicator sit on the right; a taskbar
runs along the bottom, including the **theme toggle** and the **Gate⇄Compass switch**.

## The surfaces

| Surface | Was | Purpose |
|---------|-----|---------|
| **[Agentdex](agents.md)** | Registry | All 248 agents as collectible creatures — Type, stats, trust tier, capabilities. |
| **[Party](builder.md)** | Builder | Pick a team, give it a file, simulate, run. Keyword-dispatched, sandboxed. |
| **[Battle Log](ledger.md)** | Ledger | Hash-chained audit of every run — traces, risk, anomalies, replay. |
| **[Forge](forge.md)** | Agent Forge | AI-assisted agent generator behind a static-audit gate. |
| **Workshop** | Compose | Advanced raw-DAG editor (manual runtimes/operations) + chat copilot. |
| **Energy** | Quota | Tenant usage, rate limits, resource consumption. |

## The Agentdex game layer

Every agent is classified into a **Type** (Smart-Contract, Crypto/ZK, AI/LLM, Secrets,
Web/API, Infra, Supply-Chain, Privacy, Code-Quality, Runtime) and rendered as a
deterministic procedural **creature** with flavor stats (POW/CVR/SPD). The same agent
looks identical everywhere — Agentdex, Party, Battle Log — because the sprite is seeded
from its name. It's a recognizability layer, not a reskin: the Type colors and creatures
are how you read a team at a glance.

## Gate ⇄ Compass

A single taskbar switch flips the console between two governance views:

<div class="pi-chips">
  <span class="pi-chip safe">Gate — pass / fail, KPIs, the classic view</span>
  <span class="pi-chip accent">Compass — governance as a heading you navigate</span>
</div>

The Compass is a **lens**: it changes what you *see* and the *suggested* order of a run,
never what the gate, sandbox, or ledger enforce. See the
[Governance Compass guide](compass.md).

## Bring-your-own-key (BYOK)

The Ask-AI panel and [Forge](forge.md) use **your** Anthropic API key, stored only in
`localStorage` under `pi_ai_apikey` and passed per-request as a header. The key is never
persisted server-side.

## Tech notes

- **Build target** is `esnext` — Tauri renders in the system webview (WKWebView /
  WebView2), which is evergreen, so no syntax down-leveling is needed.
- The dev server runs on `:1420` and proxies `/api` to the backend on `:8088`.
- Trust-tier chips throughout map to the [trust-tier lifecycle](../architecture/trust-tiers.md).
