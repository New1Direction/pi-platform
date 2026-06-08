# Orchestrator & Routing

The orchestrator turns a goal + context into a routed, executed, ledgered result. It
is deterministic: no probabilistic decisions on the execution path.

## The entry point

```python
PiOrchestrator.execute_goal(OrchestratorInput(goal, context)) -> OrchestratorOutput
```

`OrchestratorOutput` carries `routed_agent`, `risk_score`, `success`, and the agent's
findings.

## How a composition node becomes a goal

When the console submits a composition, each node is turned into an
`OrchestratorInput`. The **goal used for routing is the node's artifact goal** —
the keyword set in the [Builder](../console/builder.md):

```python
artifact = node.artifacts[0]
goal = artifact.get("goal") or f"{node.operation} on {node.runtime} for {node.node_id}"
ctx  = { "node_id": ..., "runtime": ..., "operation": ..., "artifacts": [...], ... }
# Artifact fields (content, filename, …) are lifted to the top of ctx so each
# agent's input_factory (ctx.get("content"), …) receives them.
```

!!! info "Why the artifact goal matters"
    A node's `runtime`/`operation` are always `pi-extension-governor`/`SANDBOX` —
    they do **not** identify an agent. Only the keyword does. Routing on a synthetic
    descriptor instead of the artifact goal sends every node to the generalist
    fallback. Routing on the artifact goal runs the agent you actually chose.

## Keyword dispatch

`AgentRouter.resolve(goal, context)`:

1. **Needle fast path** (optional) — if the Needle model is installed, it proposes an
   agent first. Falls back silently if absent.
2. **Keyword match** — the first route whose keyword appears as a word boundary in the
   lowercased goal wins:

   ```python
   any(re.search(rf"\b{re.escape(kw)}\b", goal_lower) for kw in route.keywords)
   ```

3. **Fallback** — no match → `PiMasterGeneralistFallback` (a safe no-op at risk 0).

## Method dispatch

Routing selects an agent *class*; execution calls a **bespoke method** per agent via
a closed `if/elif` chain in `orchestrator/consensus.py`:

```python
if   agent_name == "PiGitSecScanner":   return agent_inst.scan_file(perturbed)
elif agent_name == "PiArbitrageGuard":  return agent_inst.analyze_spread(perturbed)
...
else: raise ValueError(f"Unknown agent: {agent_name}")
```

This is why a newly generated agent needs **both** a router registration **and** a
dispatch branch — see the [Forge wiring recipe](../console/forge.md#wiring).

## Consensus

Agents run under a perturbation-based consensus engine: each agent is executed across
independent perturbed runs and the outputs are reconciled, so a non-deterministic or
unstable agent is caught rather than trusted blindly.

## Shields

Before routing, the orchestrator applies governance shields: prompt-injection
detection, spend/cost anomaly checks, command-safety, and defensive-only mode. In
strict mode a tripped shield blocks execution and is recorded as the routed agent
(e.g. `PIGovernShield`).
