// Truth, not flavor. Aggregate the ledger into per-agent observability — runs,
// find-rate, avg risk, reliability — and a routing-ambiguity score derived from
// the registry. NOTHING learned, predictive, or adaptive: this is the empirical
// floor the Migration Map will eventually stand on.
//
// Deliberately NOT computed here: terrain concentration / specialization. That
// needs a terrain label per run, which the ledger does not record yet — and a
// faithful concentration score cannot be faked from data we don't have. See the
// design note in docs/console/agents.md.

import type { TraceListItem, MarketplaceCapability } from '../types';

// A run "found something" when it surfaced meaningful risk or flagged an anomaly
// (same threshold the instinct field uses, so the two agree).
const FIND_RISK = 50;

export interface AgentStat {
  runs: number;
  findRate: number; // 0..1 — fraction of runs that found something
  avgRisk: number; // 0..100 — mean risk across runs
  reliability: number; // 0..1 — fraction that ran without failure
}

interface Acc {
  runs: number;
  finds: number;
  riskSum: number;
  ok: number;
}

// Per-agent aggregates keyed by routed_agent (== agent_name). Pure.
export function aggregateAgentStats(traces: TraceListItem[]): Record<string, AgentStat> {
  const acc: Record<string, Acc> = {};
  for (const t of traces) {
    const agent = t.routed_agent;
    if (!agent) continue;
    const a = acc[agent] ?? (acc[agent] = { runs: 0, finds: 0, riskSum: 0, ok: 0 });
    const risk = t.risk_score ?? 0;
    a.runs += 1;
    a.riskSum += risk;
    if (risk >= FIND_RISK || (t.anomalies_detected?.length ?? 0) > 0) a.finds += 1;
    if (t.success !== false) a.ok += 1;
  }
  const out: Record<string, AgentStat> = {};
  for (const [agent, a] of Object.entries(acc)) {
    out[agent] = {
      runs: a.runs,
      findRate: a.runs > 0 ? a.finds / a.runs : 0,
      avgRisk: a.runs > 0 ? a.riskSum / a.runs : 0,
      reliability: a.runs > 0 ? a.ok / a.runs : 0,
    };
  }
  return out;
}

export interface RoutingAmbiguity {
  shared: number; // how many OTHER agents advertise at least one identical keyword
  collidesWith: string[]; // a sample of those agents (for the tooltip)
}

const norm = (s: string): string => s.trim().toLowerCase();

// A structural property of the registry, not the ledger: when two agents
// advertise the same keyword, routing by that keyword lands on only one of them
// — the other is shadowed. This is the routing-collision finding made visible.
export function routingAmbiguity(caps: MarketplaceCapability[]): Record<string, RoutingAmbiguity> {
  // keyword → set of agent names that claim it
  const byKeyword: Record<string, Set<string>> = {};
  for (const c of caps) {
    const name = c.agent_name || c.capability_id;
    for (const tag of c.compatibility_tags ?? []) {
      const k = norm(tag);
      (byKeyword[k] ?? (byKeyword[k] = new Set())).add(name);
    }
  }
  const out: Record<string, RoutingAmbiguity> = {};
  for (const c of caps) {
    const name = c.agent_name || c.capability_id;
    const others = new Set<string>();
    for (const tag of c.compatibility_tags ?? []) {
      for (const other of byKeyword[norm(tag)] ?? []) {
        if (other !== name) others.add(other);
      }
    }
    out[name] = { shared: others.size, collidesWith: Array.from(others).slice(0, 6) };
  }
  return out;
}
