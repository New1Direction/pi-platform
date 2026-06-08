# Agents (Registry)

The Agents tab is a live browser over the 248 registered micro-agents, sourced from
`POST /api/v1/capabilities/list`.

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
- **`description`** — `"<AgentName> — keywords: …"`. The UI parses the agent name by
  splitting on ` — `.
- **`compatibility_tags`** — the router keywords; these are what the
  [Builder](builder.md) dispatches on.
- **`trust_tier`** — see the [trust-tier lifecycle](../architecture/trust-tiers.md).
  Registered platform agents are `GOVERNED`.

## Filtering

Filter by trust tier (`GOVERNED`, `AUDITED`, `VERIFIED`, `UNVERIFIED`) or search by
name, runtime, or tag. The count chip shows `matched / total`.

## Error handling

If the backend is unreachable the grid shows an explicit error and a **Retry**
button rather than a silent empty state — the same pattern is used in the Builder's
agent panel.

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

New agents that follow this pattern can be generated with the
[Agent Forge](forge.md).
