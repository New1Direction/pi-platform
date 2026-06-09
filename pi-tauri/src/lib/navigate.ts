// Phase 4 — "the route emerges AS IT RUNS." Phases 2/3 plan an order up front
// from the file + learned instincts. Phase 4 runs the party one agent at a time
// and lets each agent's REALIZED finding steer the next pick: when a region of
// risk turns out hot, dig there next; when an agent comes back clean, move on.
// True greedy descent over real results.
//
// Still a conductor, not a new enforcement path: every step is the SAME gated
// simulate→submit the batch run uses. This module is the pure decision core —
// no IO, no React — so the algorithm is deterministic and testable in isolation.

import { planRoute } from './orientation';
import type { Instincts } from './instincts';

// Which types tend to co-occur in one artifact — a reentrancy hit makes other
// contract checks worth running next; a leaked secret makes web/supply hotter.
// Heat spreads along these edges so the descent follows the real risk surface.
const NEIGHBORS: Record<string, string[]> = {
  contract: ['zk', 'runtime', 'quality'],
  zk: ['contract', 'runtime'],
  ai: ['secrets', 'web', 'privacy'],
  secrets: ['web', 'ai', 'supply', 'privacy'],
  web: ['ai', 'secrets', 'privacy'],
  infra: ['supply', 'runtime'],
  supply: ['infra', 'secrets', 'quality'],
  privacy: ['secrets', 'ai', 'web'],
  quality: ['contract', 'supply', 'runtime'],
  runtime: ['contract', 'infra', 'quality'],
  generalist: [],
};

const HEAT_SELF = 1.0; // a finding heats its own type fully
const HEAT_NEIGHBOR = 0.4; // and warms adjacent types
const HEAT_CLAMP = 2; // bound accumulation so a streak can't run away
const HEAT_WEIGHT = 0.3; // how much heat can move a pick vs. the content/instinct base
const RISK_MID = 50; // realized risk above this is "hot", below is "cooling"

export type Heat = Record<string, number>;

const clamp = (n: number, lo: number, hi: number): number => (n < lo ? lo : n > hi ? hi : n);

export function initHeat(): Heat {
  return {};
}

// Fold one agent's realized risk into the heat field (immutably). Hot finds push
// their type and neighbors up; clean results pull them down.
export function applyFinding(heat: Heat, typeKey: string, risk: number): Heat {
  const delta = (risk - RISK_MID) / 100; // +0.45 at risk 95, -0.45 at risk 5
  const next: Heat = { ...heat };
  next[typeKey] = clamp((next[typeKey] ?? 0) + delta * HEAT_SELF, -HEAT_CLAMP, HEAT_CLAMP);
  for (const n of NEIGHBORS[typeKey] ?? []) {
    next[n] = clamp((next[n] ?? 0) + delta * HEAT_NEIGHBOR, -HEAT_CLAMP, HEAT_CLAMP);
  }
  return next;
}

export interface RankedStep<T> {
  agent: T;
  typeKey: string;
  base: number; // content + instinct score (Phase 2/3)
  heat: number; // current heat for this agent's type
  score: number; // base + heat contribution — what we actually pick on
}

// Rank the remaining party for the NEXT pick. With an empty heat field (the very
// first step) this is exactly the Phase 2/3 order; each realized finding then
// bends it. tanh keeps a hot streak from dominating — heat nudges, the file and
// instincts still anchor.
export function rankRemaining<T extends { seed: string; tags: string[] }>(
  remaining: T[],
  content: string,
  instincts: Instincts | null | undefined,
  heat: Heat,
): RankedStep<T>[] {
  const planned = planRoute(remaining, content, instincts);
  const ranked = planned.map((p, i) => {
    const h = heat[p.typeKey] ?? 0;
    const score = p.blended + HEAT_WEIGHT * Math.tanh(h);
    return { agent: p.agent, typeKey: p.typeKey, base: p.blended, heat: h, score, _i: i };
  });
  ranked.sort((a, b) => b.score - a.score || a._i - b._i);
  return ranked.map(({ agent, typeKey, base, heat: h, score }) => ({ agent, typeKey, base, heat: h, score }));
}

// One-line, human-readable reason a step was chosen next — for the live log.
export function pickReason(step: RankedStep<unknown>, isFirst: boolean): string {
  if (isFirst) return 'highest content + instinct affinity';
  if (step.heat > 0.15) return `risk is hot nearby (heat +${step.heat.toFixed(2)})`;
  if (step.heat < -0.15) return `cooler ground (heat ${step.heat.toFixed(2)}) — lower priority`;
  return 'next by content + instinct';
}
