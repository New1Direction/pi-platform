// Phase 3 — "the field learns." Distil the ledger (every past run) into
// migratory instincts: per agent-type, how often history shows that type
// actually FOUND risk and how reliably it ran. Those instincts then bias the
// route — types that have found things before lead ties.
//
// Like the Phase 1 compass and the Phase 2 planner, this is a LENS:
//   • Pure + deterministic — same traces in, same instincts out.
//   • Transparent — every instinct carries a plain-language note of why.
//   • Behind the switch, additive — it changes the SUGGESTED order, never what
//     each agent does or what the gate enforces.
//   • A no-op at cold start — with no history, `learned` is false and callers
//     fall back to the pure Phase 2 content heading.

import { agentTypeOf } from './agentdex';
import { humanizeAgentName } from './humanize';
import type { TraceListItem } from '../types';

// A run "found something" when it surfaced meaningful risk or flagged an anomaly.
const RISK_FLAG = 50; // risk_score ≥ this counts as a find
// Below this many runs for a type we don't fully trust its pull — shrink it
// back toward neutral so a single fluke can't dominate the route.
const MIN_RUNS_TO_TRUST = 3;
// Below this many total runs the field hasn't learned anything worth applying.
const MIN_TOTAL_TO_LEARN = 3;

const NEUTRAL_PULL = 0.5;
const clamp01 = (n: number): number => (n < 0 ? 0 : n > 1 ? 1 : n);

export interface TypeInstinct {
  key: string;
  runs: number;
  avgRisk: number; // 0..100 — mean risk this type has surfaced
  flagRate: number; // 0..1 — fraction of runs that found something
  reliability: number; // 0..1 — fraction that ran without failure
  pull: number; // 0..1 — learned "where the action is"; 0.5 = neutral
  note: string; // one-line, human-readable, for transparency
}

export interface Instincts {
  byType: Record<string, TypeInstinct>;
  totalRuns: number;
  learned: boolean; // false → callers fall back to pure content heading
}

interface Acc {
  runs: number;
  riskSum: number;
  finds: number;
  ok: number;
}

// Distil run history into per-type instinct. Deterministic and side-effect free.
export function distillInstincts(traces: TraceListItem[]): Instincts {
  const acc: Record<string, Acc> = {};
  let totalRuns = 0;

  for (const t of traces) {
    const agent = t.routed_agent;
    if (!agent) continue; // unrouted traces carry no type signal
    // Humanize first: the matchers are word-boundary based, so the spaced form
    // ("Web Vuln Scanner") classifies where the raw CamelCase name can't.
    const key = agentTypeOf(humanizeAgentName(agent), []).key;
    const a = acc[key] ?? (acc[key] = { runs: 0, riskSum: 0, finds: 0, ok: 0 });
    const risk = t.risk_score ?? 0;
    const found = risk >= RISK_FLAG || (t.anomalies_detected?.length ?? 0) > 0;
    a.runs += 1;
    a.riskSum += risk;
    if (found) a.finds += 1;
    if (t.success !== false) a.ok += 1;
    totalRuns += 1;
  }

  const byType: Record<string, TypeInstinct> = {};
  for (const [key, a] of Object.entries(acc)) {
    const avgRisk = a.runs > 0 ? a.riskSum / a.runs : 0;
    const flagRate = a.runs > 0 ? a.finds / a.runs : 0;
    const reliability = a.runs > 0 ? a.ok / a.runs : 0;

    // Raw "this type finds things" = mostly its find-rate, nudged by how hot the
    // risk runs (avg). Then shrink toward neutral when the sample is thin.
    const raw = 0.6 * flagRate + 0.4 * (avgRisk / 100);
    const confidence = Math.min(1, a.runs / MIN_RUNS_TO_TRUST);
    const pull = clamp01(NEUTRAL_PULL + (raw - NEUTRAL_PULL) * confidence);

    byType[key] = {
      key,
      runs: a.runs,
      avgRisk,
      flagRate,
      reliability,
      pull,
      note: instinctNote(a.finds, a.runs, avgRisk),
    };
  }

  return { byType, totalRuns, learned: totalRuns >= MIN_TOTAL_TO_LEARN };
}

function instinctNote(finds: number, runs: number, avgRisk: number): string {
  if (runs === 0) return 'no history';
  if (finds === 0) return `quiet — ${runs} run${runs !== 1 ? 's' : ''}, nothing found`;
  return `found risk in ${finds}/${runs} past run${runs !== 1 ? 's' : ''} · avg ${avgRisk.toFixed(0)}`;
}

// How strongly history says a given type is "where the action is" (0..1).
// Neutral 0.5 when the field hasn't learned or has never seen this type.
export function instinctPull(instincts: Instincts | null | undefined, typeKey: string): number {
  if (!instincts || !instincts.learned) return NEUTRAL_PULL;
  return instincts.byType[typeKey]?.pull ?? NEUTRAL_PULL;
}

// The types the field has learned to watch hardest, strongest pull first.
// Only types it has actually seen find something (pull above neutral) and that
// have enough runs to trust. Empty until the field has learned.
export function watchedTypes(instincts: Instincts | null | undefined): TypeInstinct[] {
  if (!instincts || !instincts.learned) return [];
  return Object.values(instincts.byType)
    .filter(i => i.pull > NEUTRAL_PULL && i.runs >= MIN_RUNS_TO_TRUST)
    .sort((a, b) => b.pull - a.pull);
}
