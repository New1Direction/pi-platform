// Phase 2 — "the route emerges." Instead of a fixed pipeline order, read which
// way the artifact's risk points (its heading), then order a party of agents to
// descend that gradient: address the strongest-detected risk direction first.
//
// This is a PLANNING lens. It recommends an order; the real orchestrator still
// executes it and the gate still enforces. Transparent + deterministic: every
// affinity shows the exact signal it matched.

import { agentTypeOf } from './agentdex';
import { instinctPull } from './instincts';
import type { Instincts } from './instincts';

// Cheap, transparent signals that the CONTENT points toward a given type.
// (Distinct from agentdex's matchers, which classify an agent by its name.)
const CONTENT_SIGNALS: Record<string, RegExp[]> = {
  secrets: [
    /AKIA[0-9A-Z]{16}/,
    /\bsk-[A-Za-z0-9]{12,}/,
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*['"][^'"]{6,}/i,
  ],
  web: [
    /\bSELECT\b[\s\S]{0,80}\bFROM\b/i,
    /'\s*OR\s*'?1'?\s*=\s*'?1/i,
    /<script\b/i,
    /javascript:/i,
    /\.\.\/\.\.\//,
    /\b(?:csrf|ssrf|cors|redirect\s*\()/i,
  ],
  contract: [
    /pragma\s+solidity/i,
    /\bmsg\.(?:sender|value)\b/,
    /\bdelegatecall\b/i,
    /\.call\{\s*value/i,
    /\b(?:reentran|selfdestruct|tx\.origin)\b/i,
  ],
  infra: [
    /^\s*FROM\s+\S+/im,
    /^\s*(?:apiVersion|kind)\s*:/im,
    /\bresource\s+"[^"]+"\s+"[^"]+"/,
    /\bkubectl\b|\bdockerfile\b/i,
  ],
  supply: [
    /^\s*[\w.-]+\s*(?:[><=~^]=?|@)\s*[\w.*-]+/m,
    /\buses:\s*\S+@/i,
    /"dependencies"\s*:/,
  ],
  ai: [
    /\b(?:ignore (?:all )?previous|system prompt|jailbreak|prompt injection)\b/i,
    /\byou are (?:now )?an? \w+/i,
  ],
  privacy: [
    /\b\d{3}-\d{2}-\d{4}\b/, // SSN-shaped
    /\b(?:hipaa|gdpr|\bpii\b|\bpci\b)\b/i,
    /\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b/, // card-shaped
  ],
  zk: [/\b(?:circom|groth16|snark|zk-?proof|merkle root)\b/i],
  runtime: [/\b(?:tokio|goroutine|async fn|threading\.|mutex|deadlock)\b/i],
  quality: [/\b(?:TODO|FIXME|XXX)\b/, /\beval\(|\bexec\(/],
};

export interface TypeHeading {
  key: string;
  score: number; // 0..1
  matched: string; // the first signal it hit (for transparency)
}

// Score how strongly the content points toward each type.
export function contentHeading(content: string): TypeHeading[] {
  const out: TypeHeading[] = [];
  for (const [key, sigs] of Object.entries(CONTENT_SIGNALS)) {
    let hits = 0;
    let matched = '';
    for (const re of sigs) {
      const m = content.match(re);
      if (m) {
        hits += 1;
        if (!matched) matched = m[0].slice(0, 40);
      }
    }
    if (hits > 0) out.push({ key, score: Math.min(1, hits / 2), matched });
  }
  return out.sort((a, b) => b.score - a.score);
}

export interface PlannedStep<T> {
  agent: T;
  typeKey: string;
  affinity: number; // 0..1 — how strongly the content points at this agent's type
  matched: string; // the signal that drew it (empty if none)
  instinct: number; // 0..1 — learned pull from history; 0.5 = neutral / no history
  instinctNote: string; // why history weighted it (empty when nothing learned)
  blended: number; // the score actually sorted on (content-dominant)
}

// Content dominates; instinct is a quarter-weight nudge. This split is load-
// bearing for safety: a content-matched agent (affinity 1 → blended ≥ 0.75)
// always outranks a non-matched one (affinity 0 → blended ≤ 0.25), so instinct
// can only re-order agents that share the SAME content tier — never override
// the concrete signal the file gives us.
const W_CONTENT = 0.75;
const W_INSTINCT = 0.25;

// Order a party so the agent the content points hardest toward leads. When the
// field has learned instincts (Phase 3), they break ties within a content tier:
// types that have found risk in past runs lead types that have stayed quiet.
// Stable: equal blended scores keep their original order. Pass no instincts (or
// an unlearned field) and this is byte-for-byte the Phase 2 content ordering.
export function planRoute<T extends { seed: string; tags: string[] }>(
  agents: T[],
  content: string,
  instincts?: Instincts | null,
): PlannedStep<T>[] {
  const heading = contentHeading(content);
  const scoreOf = (k: string) => heading.find(h => h.key === k);
  const learned = !!instincts?.learned;
  const steps = agents.map((agent, i) => {
    const typeKey = agentTypeOf(agent.seed, agent.tags).key;
    const h = scoreOf(typeKey);
    const affinity = h?.score ?? 0;
    const pull = instinctPull(instincts, typeKey);
    const blended = learned ? affinity * W_CONTENT + pull * W_INSTINCT : affinity;
    return {
      agent,
      typeKey,
      affinity,
      matched: h?.matched ?? '',
      instinct: pull,
      instinctNote: learned ? (instincts!.byType[typeKey]?.note ?? '') : '',
      blended,
      _i: i,
    };
  });
  steps.sort((a, b) => b.blended - a.blended || a._i - b._i);
  return steps.map(({ agent, typeKey, affinity, matched, instinct, instinctNote, blended }) => ({
    agent,
    typeKey,
    affinity,
    matched,
    instinct,
    instinctNote,
    blended,
  }));
}
