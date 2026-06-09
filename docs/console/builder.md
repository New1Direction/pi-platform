# Party *(Builder)*

<div class="pi-eyebrow">Was: Builder</div>

The **Party** tab is where you assemble a team of micro-agents, give it something to
scan, simulate, and run — all without writing a raw DAG.

## Start with a playbook

A newcomer shouldn't face 248 agents cold. The empty state offers **ready-made parties**
— curated teams (Solidity Audit, Secrets Sweep, LLM Safety, Web & API, Supply Chain,
Container & Infra) that one click loads, matched against the live registry so a missing
agent is simply skipped. Or build your own from the Agentdex panel on the left.

## How it works

1. **Pick agents** (left panel). All 248 live agents load from
   `POST /api/v1/capabilities/list`. Search by name or keyword, click to add to the party.
2. Each agent joins as a node with the correct runtime/operation and a **goal pre-filled
   with the agent's first keyword**.
3. **Give it content** — pick a file or paste code/config into each node (see
   [Passing content](#passing-content-to-an-agent)).
4. **Edit the goal** if needed — the goal text is what routes the node to a specific
   agent (see below).
5. **Simulate** — a dry run that validates the DAG, bounds, policy, and risk without
   executing any agent.
6. **Approve & Run** — executes the party; results are hash-chained into the
   [Battle Log](ledger.md).

!!! tip "Let the route emerge"
    In **Compass** mode the Party gains a **Navigate** panel that orders the team by
    where the file's risk actually points — and a **Run live** mode where the route
    adapts to each agent's realized finding. See the [Governance Compass](compass.md).

## Every node uses the same runtime

This is the key architectural fact: **all 248 micro-agents run under the same
runtime and operation**:

```json
{ "runtime": "pi-extension-governor", "operation": "SANDBOX" }
```

Agents are *not* differentiated by runtime. They're differentiated by the **goal
keyword**, which the orchestrator matches against each agent's registered keywords.

## Keyword dispatch

When you run a node, the backend routes on the node's **artifact goal** — the
keyword you set in the Party. For example:

| Goal keyword | Routes to | Example finding |
|--------------|-----------|-----------------|
| `dependency scan` | `PiGitSecScanner` | unpinned `flask>=1.0` → risk 75 |
| `reentrancy scan` | `PiReentrancySentry` | missing checks-effects-interactions |
| `leak scan` | `PiPromptLeakBuster` | credential/egress leak |

If the goal matches no registered keyword, the orchestrator falls back to
`PiMasterGeneralistFallback` (a no-op pass at risk 0). Because the Party pre-fills
each node's goal with the agent's own keyword, the default flow always routes
correctly.

!!! info "Routing fix"
    Earlier, the submit path routed on a synthetic descriptor
    (`"SANDBOX on pi-extension-governor for n1"`) that matched no keyword, so the
    chosen agent never actually ran. The submit path now routes on
    `artifacts[0].goal` and lifts artifact fields (`content`, `filename`, …) into
    the agent's input context. See
    [Orchestrator & Routing](../architecture/orchestrator-routing.md).

## Passing content to an agent

Each agent's input is built from the node's artifact. Put the material to scan in
the artifact alongside the goal:

```json
{
  "goal": "dependency scan",
  "content": "requests\nflask>=1.0\n",
  "filename": "requirements.txt"
}
```

The backend lifts `content`, `filename`, etc. into the agent's input so its
`input_factory` receives them.

## What a node compiles to

```json
{
  "node_id": "n1",
  "runtime": "pi-extension-governor",
  "operation": "SANDBOX",
  "artifacts": [{ "goal": "dependency scan", "content": "…" }],
  "required_schema_version": "1.0.0",
  "bounds": { "max_depth": 3, "max_fanout": 4 },
  "dependencies": []
}
```

Sequential nodes chain via `dependencies` (node *n* depends on *n-1*).
