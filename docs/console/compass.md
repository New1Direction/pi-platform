# Governance Compass

<div class="pi-eyebrow">Compass mode · a lens, behind one switch</div>

Most tools treat governance as a **gate**: pass or fail. The **Governance Compass**
reframes it as a **heading** — a direction you navigate. It reads the signals the
orchestrator already emits, the file in front of you, and what past runs learned, and
turns them into orientation.

!!! note "It is a lens — it never enforces"
    The Compass changes what you **see** and the **suggested** order of a run. It never
    changes what the gate, the sandbox, or the ledger **enforce**. Flip the taskbar
    switch back to **Gate** and every wall is exactly where it was.

    > *Semantic cognition derives structure. Infrastructure enforces truth.*

It ships in four phases, all behind the single Gate⇄Compass switch — each additive, each
a provable no-op when there's nothing to act on.

## The four phases

<div class="pi-phases">
  <div class="pi-phase">
    <div class="pi-phase__n">Phase 1 — Compass</div>
    <div class="pi-phase__h">Which way is north</div>
    <p class="pi-phase__b">Composes the orchestrator's signals — risk, trust, anomaly,
    instability — into a single heading. North is Safe; the needle is the resultant pull
    across every run. Shown as the fleet heading in the Battle Log, and per-run on any
    trace.</p>
  </div>
  <div class="pi-phase">
    <div class="pi-phase__n">Phase 2 — Navigate</div>
    <div class="pi-phase__h">The route emerges</div>
    <p class="pi-phase__b">Instead of a fixed pipeline order, the Party reads which way
    the <em>file's</em> risk points — a transparent, deterministic content-heading where
    every match shows the exact signal it hit — then orders the team to descend that
    gradient, strongest-risk first. The order emerges from the file, not a preset.</p>
  </div>
  <div class="pi-phase">
    <div class="pi-phase__n">Phase 3 — Instincts</div>
    <div class="pi-phase__h">The field learns</div>
    <p class="pi-phase__b">Distils the ledger — every past run — into migratory
    instincts: per agent-Type, how often history shows it actually <em>found</em> risk
    and how reliably it ran. Proven finders break ties in the route. 🦋 A cold ledger is a
    no-op; the field only learns once it has migrations to inherit.</p>
  </div>
  <div class="pi-phase">
    <div class="pi-phase__n">Phase 4 — Live Navigate</div>
    <div class="pi-phase__h">It adapts as it runs</div>
    <p class="pi-phase__b">Runs the party one agent at a time, reads each agent's
    <em>realized</em> finding from the ledger, and lets that finding heat or cool the
    field so the next pick is re-ranked from real results. True greedy descent — when a
    region of risk turns out hot, dig there next; when an agent comes back clean, move
    on.</p>
  </div>
</div>

## The safety invariants

Every phase is designed so it **cannot** override the concrete signal or the gate:

- **Content dominates instinct.** Instinct is weighted ¼ against content's ¾, so a
  content-matched agent always outranks a non-matched one — instinct can only reorder
  agents *within* the same content tier, never cross it.
- **Cold start is a no-op.** With an empty ledger, Navigate is byte-for-byte the
  file-only order; instincts contribute nothing until the field has learned.
- **Every live step is the same gate.** Phase 4 runs the identical
  `simulate → submit` the batch run uses; the gate stays authoritative per step — a
  blocked node is *skipped*, never forced. No backend path is bypassed.

<div class="pi-chips">
  <span class="pi-chip safe">North = Safe</span>
  <span class="pi-chip elevated">deflection = drift</span>
  <span class="pi-chip critical">180° = pure risk</span>
</div>

## Using it

1. Flip the taskbar switch to **Compass**.
2. In the **[Party](builder.md)**, pick a team and drop in a file. The **Navigate** panel
   shows where the file's risk points and the order it suggests — hit **Apply this order**
   for a static route, or **◆ Run live** to let the route adapt to each finding.
3. In the **[Battle Log](ledger.md)**, the top strip becomes the fleet **Compass** and a
   **Migratory instincts** readout shows what the field has learned.
4. Flip back to **Gate** anytime — nothing you ran changes; you just see the classic
   pass/fail view again.

## Why a compass

The metaphor is the monarch butterfly: no single butterfly holds the map, yet the swarm
migrates thousands of miles by each one orienting locally. The Compass is that —
**global coordination through local orientation.** Planning emerges; enforcement stays
exactly where it was.
