// Agentdex — the "Pokémon layer" over the 248 micro-agents.
// Pure, deterministic helpers: every agent gets a Type, flavor Stats, and a
// procedural pixel "creature" sprite — all derived from its name + keywords so
// real art (when you drop it in) can replace the procedural sprites later.

export type AgentType = { key: string; label: string; color: string; emoji: string };

export const TYPES: AgentType[] = [
  { key: 'contract',   label: 'Smart-Contract', color: '#a368ff', emoji: '🔮' },
  { key: 'zk',         label: 'Crypto / ZK',    color: '#13c2b0', emoji: '🧮' },
  { key: 'ai',         label: 'AI / LLM',       color: '#ff6ec7', emoji: '🧠' },
  { key: 'secrets',    label: 'Secrets',        color: '#ffb400', emoji: '🔑' },
  { key: 'web',        label: 'Web / API',      color: '#3aa0ff', emoji: '🌐' },
  { key: 'infra',      label: 'Infra',          color: '#5fd38a', emoji: '🐳' },
  { key: 'supply',     label: 'Supply-Chain',   color: '#ff8a3a', emoji: '📦' },
  { key: 'privacy',    label: 'Privacy',        color: '#c79bff', emoji: '🛡️' },
  { key: 'quality',    label: 'Code-Quality',   color: '#9aa6b0', emoji: '🔧' },
  { key: 'runtime',    label: 'Runtime',        color: '#ff5a6a', emoji: '⚙️' },
  { key: 'generalist', label: 'Generalist',     color: '#8a8a8a', emoji: '✦' },
];
const TYPE_BY_KEY: Record<string, AgentType> = Object.fromEntries(TYPES.map(t => [t.key, t]));

// Ordered by specificity — first match wins.
const TYPE_MATCHERS: [string, RegExp][] = [
  ['zk',       /\b(zk|circom|snark|proof|eip[- ]?712|ecrecover|signature|merkle|knowledge)\b/],
  ['contract', /\b(solidity|reentran|erc[- ]?\d|eip[- ]?\d|vyper|defi|oracle|vault|flash|delegatecall|tx\.?origin|slippage|mev|uniswap|bridge|selfdestruct|pragma|arithmetic|overflow|storage|solana|anchor|mempool|arbitrage|token)\b/],
  ['ai',       /\b(llm|prompt|hallucinat|jailbreak|injection|chain[- ]?of[- ]?thought|system[- ]?prompt|egress|sanitiz)\b/],
  ['secrets',  /\b(secret|credential|api[- ]?key|token|hardcoded|leak|rotation|entropy)\b/],
  ['web',      /\b(sql|xss|csrf|ssrf|cors|owasp|web|redirect|http|jwt|auth|grpc|phish)\b/],
  ['infra',    /\b(docker|kubernetes|k8s|container|terraform|iac|cloud|firewall|nginx|deploy|backup|escape)\b/],
  ['supply',   /\b(depend|sbom|supply|package|github[- ]?action|signing|lockfile|version|pipeline)\b/],
  ['privacy',  /\b(privacy|pii|hipaa|pci|gdpr|anonymi|retention|data[- ]?flow|encryption|sensitive|compliance)\b/],
  ['quality',  /\b(magic[- ]?number|dead[- ]?code|shadow|recursion|complexity|\bast\b|lint|tdd|changelog|readme|commit|interface|depreciat|refactor|typescript|logging)\b/],
  ['runtime',  /\b(runtime|memory|deadlock|tokio|constant[- ]?time|hot[- ]?path|anomaly|tui|resource|reflection|swarm)\b/],
];

export function agentTypeOf(agentName: string, keywords: string[]): AgentType {
  const hay = (agentName + ' ' + keywords.join(' ')).toLowerCase();
  for (const [key, re] of TYPE_MATCHERS) if (re.test(hay)) return TYPE_BY_KEY[key];
  return TYPE_BY_KEY.generalist;
}

function hash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}

export type Stats = { POW: number; CVR: number; SPD: number };

// Flavor stats (it's a game) — deterministic so a given agent always looks the
// same. CVR (coverage) tracks real breadth (keyword count); POW/SPD are seeded.
export function agentStats(agentName: string, keywords: string[]): Stats {
  const h = hash(agentName);
  return {
    POW: 45 + (h % 55),
    CVR: Math.min(99, keywords.length * 11 + 34),
    SPD: 30 + ((h >>> 9) % 66),
  };
}

// 7×7 horizontally-symmetric pixel "creature" silhouette, seeded by name.
export function spriteGrid(seed: string): boolean[][] {
  const h = hash(seed), h2 = hash(seed + '#');
  const N = 7, HALF = 4;
  const grid: boolean[][] = Array.from({ length: N }, () => new Array(N).fill(false));
  for (let r = 1; r < 6; r++) {
    for (let c = 0; c < HALF; c++) {
      const idx = r * HALF + c;
      const src = idx < 32 ? h : h2;
      const on = ((src >>> (idx % 32)) & 1) === 1 || c === HALF - 1; // center column biased on → solid body
      grid[r][c] = on;
      grid[r][N - 1 - c] = on;
    }
  }
  // guarantee a creature shape: head crown + eye row + feet
  grid[1][3] = true;
  grid[2][2] = grid[2][4] = true;            // eye sockets
  grid[5][1] = grid[5][5] = false;           // trim shoulders
  grid[6][2] = grid[6][4] = true;            // feet
  return grid;
}
