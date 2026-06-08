# Trust Tiers

Every capability carries a `trust_tier` that reflects how much scrutiny it has
passed. Tiers are a one-way lifecycle: code only moves *up* as it earns trust.

```
UNVERIFIED  →  VERIFIED  →  AUDITED  →  GOVERNED
```

| Tier | Meaning | How it's reached |
|------|---------|------------------|
| **UNVERIFIED** | AI-generated, not human-reviewed. Quarantined in `pending/`, runnable by nothing. | Output of the [Agent Forge](../console/forge.md). |
| **VERIFIED** | A human reviewed and promoted the code into the package, registered, and wired its dispatch branch. | Manual review + the [wiring recipe](../console/forge.md#wiring). |
| **AUDITED** | Has tests that pass and exercise its behavior. | Test coverage + CI green. |
| **GOVERNED** | Security sign-off; safe to run in production compositions. | Governance review. The 248 registered platform agents are `GOVERNED`. |

## Why the gate matters

The jump from `UNVERIFIED` to `VERIFIED` is deliberately manual and deliberately
high-friction:

- Generated agents are written to `src/pi_micro_agents/pending/`, which is
  **git-ignored** — unverified code physically cannot enter version control via a
  stray `git add .`.
- Nothing imports `pending/`; no loader sweeps it; tests don't collect it.
- The orchestrator's dispatch chain raises `ValueError("Unknown agent")` for anything
  without an explicit branch — so even a *registered* unverified agent can't execute
  until a human adds that branch.

The result: AI can *propose* an agent, but a human is always the one who promotes it
into the trusted execution path.
