# Builder

The Builder lets you assemble micro-agents into an execution pipeline, simulate it,
and run it — all without writing a raw DAG.

## How it works

1. **Browse the registry** (left panel). All 248 live agents load from
   `POST /api/v1/capabilities/list`. Search by name or keyword.
2. **Click an agent** to add it as a pipeline node. Each node is created with the
   correct runtime/operation and a **goal pre-filled with the agent's first
   keyword**.
3. **Edit the goal** if needed — the goal text is what routes the node to a specific
   agent (see below).
4. **Simulate** — a dry run that validates the DAG, bounds, policy, and risk without
   executing any agent.
5. **Approve & Run** — executes the pipeline; results are hash-chained into the
   [Ledger](ledger.md).

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
keyword you set in the Builder. For example:

| Goal keyword | Routes to | Example finding |
|--------------|-----------|-----------------|
| `dependency scan` | `PiGitSecScanner` | unpinned `flask>=1.0` → risk 75 |
| `reentrancy scan` | `PiReentrancySentry` | missing checks-effects-interactions |
| `leak scan` | `PiPromptLeakBuster` | credential/egress leak |

If the goal matches no registered keyword, the orchestrator falls back to
`PiMasterGeneralistFallback` (a no-op pass at risk 0). Because the Builder pre-fills
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
