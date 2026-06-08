# Agent Forge

The Agent Forge is an AI-assisted generator for new micro-agents. You describe what
you want, Claude drafts a module that follows the platform pattern, the code is
**statically audited**, and only audit-passing code can be saved — as `UNVERIFIED`,
into a quarantined `pending/` directory.

!!! danger "Generated agents cannot run until a human wires them in"
    Forge output never auto-registers and never auto-executes. It lands in
    `src/pi_micro_agents/pending/`, which is git-ignored and imported by nothing. A
    human must review, promote, and wire it (see [Wiring](#wiring) below) before it
    can run. This is the `UNVERIFIED → VERIFIED` step of the
    [trust lifecycle](../architecture/trust-tiers.md).

## Endpoints

| Endpoint | Purpose |
|----------|---------|
| `POST /api/v1/forge/generate` | Description + keywords → Claude generates agent code (BYOK). |
| `POST /api/v1/forge/audit` | Static analysis of the code (no key required). |
| `POST /api/v1/forge/save` | Re-audits, then writes to `pending/` as `UNVERIFIED`. |

## The audit gate

`/forge/audit` runs three layers of checks. Any **CRITICAL** or **HIGH** finding
blocks `/forge/save` (returns `422`):

- **Syntax** — the code must `ast.parse` cleanly.
- **Dangerous patterns** — `eval`, `exec`, `os.system`, `subprocess(..., shell=True)`,
  dynamic `__import__`, hardcoded credentials.
- **Structural** — must contain `is_strict_mode`, the `resolve_strict_mode` import,
  a Pydantic `BaseModel`, an `AgentRouter.register(...)` call, and a
  `self.agent_name` assignment.

## Workflow in the UI

1. Fill in **description**, **keywords**, and an optional **example input**.
2. Paste your Anthropic key (stored locally as `pi_ai_apikey`, sent per-request).
3. **Generate** → the code appears and is **auto-audited**. Save is disabled until
   the audit passes.
4. **Save to pending/** → the file lands as `pi_<snake_case_name>.py`,
   `trust_tier=UNVERIFIED`.

## Wiring

Saving is only the first step. The **Code** tab shows the full recipe a reviewer
follows to promote a generated agent — because registering it in the router alone is
**not** enough to make it run (the orchestrator dispatches each agent via an explicit
branch):

```python
# 1. Promote out of the quarantine
mv src/pi_micro_agents/pending/pi_x.py src/pi_micro_agents/pi_x.py

# 2. Import it in orchestrator/router.py
from pi_micro_agents.pi_x import PiX, PiXInput

# 3. Register the route
AgentRouter.register(
    agent_name="PiX", keywords=[...], agent_class=PiX,
    input_factory=lambda goal, ctx: PiXInput(content=ctx.get("content", "")),
)

# 4. Add a dispatch branch in orchestrator/consensus.py
elif agent_name == "PiX":
    return agent_inst.scan(perturbed)
```

Step 4 matters: the consensus dispatcher is a closed `if/elif` chain that ends in
`raise ValueError("Unknown agent")`. An agent that's registered but has no dispatch
branch is routable but not executable.
