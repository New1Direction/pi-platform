import { useState, useEffect } from 'react';
import { Search, Play, Send, AlertTriangle, CheckCircle2, XCircle, ChevronRight, X, FileUp, Compass } from 'lucide-react';
import { listAllCapabilities, simulateComposition, submitComposition, getTenantId, getLedgerTraces } from '../lib/api';
import { humanizeAgentName } from '../lib/humanize';
import { agentTypeOf, TYPES } from '../lib/agentdex';
import { planRoute, contentHeading } from '../lib/orientation';
import { distillInstincts } from '../lib/instincts';
import type { Instincts } from '../lib/instincts';
import { initHeat, applyFinding, rankRemaining, pickReason } from '../lib/navigate';
import { Creature } from '../components/Creature';
import type { MarketplaceCapability, SimulationReport } from '../types';
import { Tooltip } from '../components/Tooltip';

const TYPE_LABEL: Record<string, { label: string; color: string; emoji: string }> = Object.fromEntries(
  TYPES.map(t => [t.key, { label: t.label, color: t.color, emoji: t.emoji }]),
);

// Stable per-agent seed for the creature sprite — same value the Agentdex uses,
// so a given agent looks identical everywhere.
const seedOf = (c: MarketplaceCapability) => c.agent_name || c.capability_id.replace(/^cap_/, '');

// ─── Types ────────────────────────────────────────────────────────────────────

type PipelineNode = {
  id: string;
  capId: string;
  name: string;
  tags: string[];
  goal: string;
  content: string;   // the file/code/text the agent scans
  filename: string;  // optional filename hint (some agents key off extension)
  seed: string;      // stable creature seed (= the agent's raw name)
};

type Phase = 'configure' | 'simulating' | 'review' | 'running' | 'done';

// Phase 4 — one stop on the live descent. The route is the sequence of these,
// each chosen from the realized risk of the ones before it.
type LiveStep = {
  nodeId: string;
  name: string;
  seed: string;
  typeKey: string;
  status: 'running' | 'done' | 'blocked' | 'error';
  risk: number | null; // realized once done
  found: string[]; // anomalies surfaced
  reason: string; // why this agent was picked next
  detail?: string; // gate/error note
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function agentName(cap: MarketplaceCapability): string {
  return humanizeAgentName(cap.agent_name || cap.capability_id.replace(/^cap_/, ''));
}

const RISK_COLOR: Record<string, string> = {
  NONE: '#006622', LOW: '#006622', MEDIUM: '#7a4800', HIGH: '#cc0022', CRITICAL: '#cc0022',
};

function buildRequest(pipeline: PipelineNode[], sessionId: string) {
  return {
    request_id: crypto.randomUUID(),
    tenant_id: getTenantId(),
    console_session_id: sessionId,
    created_at: new Date().toISOString(),
    nodes: pipeline.map((n, i) => ({
      node_id: n.id,
      runtime: 'pi-extension-governor',
      operation: 'SANDBOX',
      artifacts: [{ goal: n.goal, content: n.content, filename: n.filename }],
      required_schema_version: '1.0.0',
      bounds: { max_depth: 3, max_fanout: 4 },
      dependencies: i > 0 ? [pipeline[i - 1].id] : [],
    })),
    edges: [],
    global_policy_ref: 'default',
    global_schema_version: '1.0.0',
    global_bounds: { max_depth: 3, max_fanout: 4 },
    simulation_only: false,
    approved_by_user: false,
    strict: true,
    request_hash: '',
  };
}

function makeNode(cap: MarketplaceCapability, idx: number): PipelineNode {
  return {
    id: `n${idx + 1}`, capId: cap.capability_id, name: agentName(cap),
    tags: cap.compatibility_tags, goal: cap.compatibility_tags[0] ?? '',
    content: '', filename: '', seed: seedOf(cap),
  };
}

// Ready-made "parties" — curated teams so a newcomer picks one instead of
// facing 248 agents. `picks` are agent-name substrings, matched against the
// live registry (missing ones are skipped, so this can't break).
type Playbook = { key: string; name: string; emoji: string; color: string; desc: string; picks: string[] };
const PLAYBOOKS: Playbook[] = [
  { key: 'solidity', name: 'Solidity Audit', emoji: '🔮', color: '#a368ff', desc: 'Smart-contract security sweep',
    picks: ['Reentrancy', 'AccessControl', 'Arithmetic', 'FlashLoan', 'DelegateCall'] },
  { key: 'secrets', name: 'Secrets Sweep', emoji: '🔑', color: '#ffb400', desc: 'Hunt leaked keys & credentials',
    picks: ['HardcodedSecret', 'GitSecretLeak', 'PromptLeak', 'SecretsManager'] },
  { key: 'llm', name: 'LLM Safety', emoji: '🧠', color: '#ff6ec7', desc: 'Prompt-injection & output checks',
    picks: ['PromptInjectionSentry', 'HallucinationDetector', 'OutputSanitizer', 'SystemPromptHijack'] },
  { key: 'web', name: 'Web & API', emoji: '🌐', color: '#3aa0ff', desc: 'OWASP-style web/API scan',
    picks: ['APIOWASPScanner', 'WebVulnScanner', 'PhishingShield', 'TxOriginSentry'] },
  { key: 'supply', name: 'Supply Chain', emoji: '📦', color: '#ff8a3a', desc: 'Deps, SBOM & signing',
    picks: ['GitSecScanner', 'DependencyVuln', 'SBOMValidator', 'SupplyChain', 'CodeSigning'] },
  { key: 'infra', name: 'Container & Infra', emoji: '🐳', color: '#5fd38a', desc: 'Docker, K8s & IaC',
    picks: ['DockerImageScanner', 'KubernetesSecurity', 'IaCScanner', 'FirewallRule', 'ContainerEscape'] },
];

// ─── AgentCard ────────────────────────────────────────────────────────────────

function AgentCard({ cap, onAdd }: { cap: MarketplaceCapability; onAdd: (c: MarketplaceCapability) => void }) {
  const name = agentName(cap);
  const seed = seedOf(cap);
  const type = agentTypeOf(seed, cap.compatibility_tags);
  const tipText = `${name}\n\n${type.emoji} ${type.label}\n\nScans for:\n${cap.compatibility_tags.map(t => `· ${t}`).join('\n')}\n\nClick to add to your party.`;

  return (
    <Tooltip tip={tipText} pos="right" wrapStyle={{ display: 'block' }}>
      <button
        onClick={() => onAdd(cap)}
        style={{
          display: 'flex', alignItems: 'center', gap: 9,
          padding: '6px 10px', width: '100%', textAlign: 'left',
          background: 'transparent', border: 'none',
          borderBottom: '1px solid var(--chrome-dd)', borderLeft: `3px solid ${type.color}`,
          cursor: 'pointer', transition: 'background 60ms',
        }}
        onMouseEnter={e => (e.currentTarget.style.background = 'var(--surface-2)')}
        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
      >
        <div style={{ width: 28, height: 28, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Creature seed={seed} color={type.color} size={26} />
        </div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{
            fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700, color: 'var(--text)',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
          }}>
            {name}
          </div>
          <div style={{ fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 600, color: type.color, marginTop: 1 }}>
            {type.emoji} {type.label}
          </div>
        </div>
      </button>
    </Tooltip>
  );
}

// ─── BuilderView ──────────────────────────────────────────────────────────────

export function BuilderView({ sessionId, govMode = 'gate' }: { sessionId: string | null; govMode?: 'gate' | 'compass' }) {
  const [agents, setAgents] = useState<MarketplaceCapability[]>([]);
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [pipeline, setPipeline] = useState<PipelineNode[]>([]);
  const [phase, setPhase] = useState<Phase>('configure');
  const [report, setReport] = useState<SimulationReport | null>(null);
  const [canExec, setCanExec] = useState(false);
  const [ledgerId, setLedgerId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [agentError, setAgentError] = useState<string | null>(null);

  // Phase 3 — migratory instincts distilled from past runs. Only fetched in
  // compass mode; a cold/empty ledger leaves this null → planRoute falls back
  // to the pure Phase 2 content ordering.
  const [instincts, setInstincts] = useState<Instincts | null>(null);

  // Phase 4 — live adaptive descent (compass mode, opt-in). Separate from the
  // batch Simulate/Run flow, which is untouched.
  const [liveSteps, setLiveSteps] = useState<LiveStep[]>([]);
  const [liveStatus, setLiveStatus] = useState<'idle' | 'running' | 'done'>('idle');

  useEffect(() => {
    if (govMode !== 'compass') return;
    let alive = true;
    getLedgerTraces(200, 0)
      .then(r => { if (alive) setInstincts(distillInstincts(r.traces)); })
      .catch(() => { if (alive) setInstincts(null); });
    return () => { alive = false; };
  }, [govMode]);

  const loadAgents = () => {
    setAgentsLoading(true);
    setAgentError(null);
    listAllCapabilities()
      .then(r => setAgents(r.capabilities))
      .catch(e => setAgentError(String(e)))
      .finally(() => setAgentsLoading(false));
  };

  useEffect(() => { loadAgents(); }, []);

  const filtered = search.trim()
    ? agents.filter(a => {
        const q = search.toLowerCase();
        return agentName(a).toLowerCase().includes(q) ||
          a.compatibility_tags.some(t => t.includes(q));
      })
    : agents;

  const addAgent = (cap: MarketplaceCapability) => {
    setPipeline(prev => [...prev, makeNode(cap, prev.length)]);
    setPhase('configure');
    setReport(null);
    setError(null);
  };

  const loadPlaybook = (pb: Playbook) => {
    const picked: MarketplaceCapability[] = [];
    for (const pat of pb.picks) {
      const cap = agents.find(c => (c.agent_name || '').toLowerCase().includes(pat.toLowerCase()) && !picked.includes(c));
      if (cap) picked.push(cap);
    }
    if (picked.length) {
      setPipeline(picked.map((c, i) => makeNode(c, i)));
      setPhase('configure');
      setReport(null);
      setError(null);
    }
  };

  const removeNode = (id: string) =>
    setPipeline(prev =>
      prev.filter(n => n.id !== id).map((n, i) => ({ ...n, id: `n${i + 1}` }))
    );

  // Phase 2 — reorder the party to the gradient-emergent route.
  const applyRoute = (ordered: PipelineNode[]) => {
    setPipeline(ordered.map((n, i) => ({ ...n, id: `n${i + 1}` })));
    setReport(null);
    setError(null);
  };

  const updateNode = (id: string, patch: Partial<PipelineNode>) =>
    setPipeline(prev => prev.map(n => n.id === id ? { ...n, ...patch } : n));

  const updateGoal = (id: string, goal: string) => updateNode(id, { goal });

  // Read a picked file (browser File API — works inside the Tauri webview) into
  // the node's content + filename. Capped to keep the request under the backend
  // 1 MiB limit.
  const MAX_SCAN_BYTES = 512 * 1024;
  const readFileIntoNode = (id: string, file: File) => {
    if (file.size > MAX_SCAN_BYTES) {
      updateNode(id, { content: `// file too large (${Math.round(file.size / 1024)} KB > 512 KB cap)`, filename: file.name });
      return;
    }
    const reader = new FileReader();
    reader.onload = () => updateNode(id, { content: String(reader.result ?? ''), filename: file.name });
    reader.readAsText(file);
  };

  const simulate = async () => {
    if (!sessionId || pipeline.length === 0) return;
    setPhase('simulating'); setError(null); setReport(null);
    try {
      const req = buildRequest(pipeline, sessionId);
      const r = await simulateComposition(req);
      setReport(r.report); setCanExec(r.can_execute); setPhase('review');
    } catch (e) { setError(String(e)); setPhase('configure'); }
  };

  const run = async () => {
    if (!sessionId || !canExec) return;
    setPhase('running'); setError(null);
    try {
      const req = { ...buildRequest(pipeline, sessionId), approved_by_user: true };
      const r = await submitComposition(req) as { core_ledger_id?: string };
      setLedgerId(r.core_ledger_id ?? null); setPhase('done');
    } catch (e) { setError(String(e)); setPhase('review'); }
  };

  // Read back the realized finding for the agent we just ran: newest matching
  // trace wins, highest risk among its (possibly consensus-paired) traces.
  const readFinding = async (agentSeed: string): Promise<{ risk: number; found: string[] }> => {
    const tr = await getLedgerTraces(10, 0);
    const mine = tr.traces.filter(t => t.routed_agent === agentSeed);
    if (mine.length === 0) return { risk: 0, found: [] };
    const top = mine.reduce((a, b) => ((b.risk_score ?? 0) > (a.risk_score ?? 0) ? b : a));
    return { risk: top.risk_score ?? 0, found: top.anomalies_detected ?? [] };
  };

  // Run the party LIVE — one agent at a time, showing each agent execute and what
  // it found, as it happens. Every step is the SAME gated simulate→submit the batch
  // run uses. `adaptive` (Compass mode) re-ranks who goes next from realized
  // findings (the route emerges); non-adaptive (Gate mode, the default) just runs
  // your party in order — but with full per-agent visibility either way.
  const runLive = async (adaptive = false) => {
    if (!sessionId || pipeline.length === 0 || liveStatus === 'running') return;
    setError(null);
    setLiveStatus('running');
    const content = pipeline.map(n => n.content).join('\n').trim();
    let heat = initHeat();
    let remaining = [...pipeline];
    const steps: LiveStep[] = [];
    setLiveSteps([]);
    const patch = (i: number, p: Partial<LiveStep>) => {
      steps[i] = { ...steps[i], ...p };
      setLiveSteps([...steps]);
    };
    try {
      while (remaining.length > 0) {
        let node: PipelineNode;
        let typeKey: string;
        let reason: string;
        if (adaptive) {
          const top = rankRemaining(remaining, content, instincts, heat)[0];
          node = top.agent;
          typeKey = top.typeKey;
          reason = pickReason(top, steps.length === 0);
          remaining = remaining.filter(n => n.id !== node.id);
        } else {
          const next = remaining.shift();
          if (!next) break;
          node = next;
          typeKey = agentTypeOf(node.seed, node.tags).key;
          reason = 'in party order';
        }
        const i = steps.length;
        steps.push({
          nodeId: node.id, name: node.name, seed: node.seed, typeKey,
          status: 'running', risk: null, found: [], reason,
        });
        setLiveSteps([...steps]);

        const req = buildRequest([node], sessionId);
        const sim = await simulateComposition(req);
        if (!sim.can_execute) {
          patch(i, {
            status: 'blocked',
            detail: sim.report.risk_details[0] || sim.report.policy_violations[0] || 'gate blocked this step',
          });
          continue; // gate is authoritative — skip it, keep going
        }
        await submitComposition({ ...req, approved_by_user: true });
        const f = await readFinding(node.seed);
        patch(i, { status: 'done', risk: f.risk, found: f.found });
        if (adaptive) heat = applyFinding(heat, typeKey, f.risk);
      }
      setLiveStatus('done');
    } catch (e) {
      const last = steps.length - 1;
      if (last >= 0 && steps[last].status === 'running') patch(last, { status: 'error', detail: String(e) });
      setError(String(e));
      setLiveStatus('done');
    }
  };

  const reset = () => {
    setPhase('configure'); setReport(null); setLedgerId(null); setError(null);
    setLiveSteps([]); setLiveStatus('idle');
  };

  const isActive = phase === 'simulating' || phase === 'running' || liveStatus === 'running';

  return (
    <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

      {/* ── Agent Browser ──────────────────────────────────────────── */}
      <div style={{
        width: 224, flexShrink: 0, borderRight: '1px solid var(--chrome-dd)',
        display: 'flex', flexDirection: 'column', background: 'var(--surface-2)',
      }}>

        {/* Panel header */}
        <div style={{
          padding: '8px 10px', background: 'var(--chrome)',
          borderBottom: '1px solid var(--chrome-dd)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span style={{ fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Pick Agents
          </span>
          <button
            onClick={loadAgents}
            disabled={agentsLoading}
            style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
            title="Reload agent list"
          >
            {agentsLoading ? '…' : `↺ ${agents.length}`}
          </button>
        </div>

        {/* Search bar */}
        <div style={{ padding: '6px 8px', borderBottom: '1px solid var(--chrome-dd)', background: 'var(--chrome)' }}>
          <div style={{
            display: 'flex', alignItems: 'center',
            border: 'var(--bw)', background: 'var(--surface)',
            boxShadow: 'inset 1px 1px 0 var(--chrome-dd)',
          }}>
            <Search size={11} style={{ margin: '0 6px', color: 'var(--text)', flexShrink: 0 }} />
            <input
              className="input"
              style={{ border: 'none', boxShadow: 'none', fontSize: 12, padding: '4px 4px' }}
              placeholder="search agents or keywords…"
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
        </div>

        {/* Agent list */}
        <div style={{ flex: 1, overflow: 'auto' }}>
          {agentsLoading && (
            <div style={{ padding: 16, fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text)', textAlign: 'center' }}>
              loading…
            </div>
          )}
          {!agentsLoading && agentError && (
            <div style={{ margin: 10 }}>
              <div style={{ padding: '8px 10px', background: '#ffe0e6', border: '1px solid #cc0022', fontFamily: 'var(--font-mono)', fontSize: 12, color: '#880011', marginBottom: 6 }}>
                {agentError}
              </div>
              <button className="btn btn-sm" onClick={loadAgents} style={{ width: '100%' }}>
                ↺ Retry
              </button>
            </div>
          )}
          {!agentsLoading && !agentError && filtered.length === 0 && (
            <div style={{ padding: 16, fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text)', textAlign: 'center' }}>
              {agents.length === 0 ? 'no agents loaded' : 'no agents match'}
            </div>
          )}
          {filtered.map(cap => (
            <AgentCard key={cap.capability_id} cap={cap} onAdd={addAgent} />
          ))}
        </div>

        {/* Footer hint */}
        <div style={{
          padding: '6px 10px', borderTop: '1px solid var(--chrome-dd)',
          fontFamily: 'var(--font-ui)', fontSize: 12, color: 'var(--text)',
          background: 'var(--chrome)', lineHeight: 1.5,
        }}>
          Tap an agent to add it to your party. Hover for what it scans.
        </div>
      </div>

      {/* ── Pipeline Canvas ────────────────────────────────────────── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        {/* Canvas header */}
        <div style={{
          padding: '8px 14px', background: 'var(--chrome)',
          borderBottom: '1px solid var(--chrome-dd)',
          flexShrink: 0, display: 'flex', alignItems: 'center', gap: 10,
        }}>
          <span style={{ fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Your Party
          </span>
          {pipeline.length > 0 && (
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text)' }}>
              {pipeline.length} agent{pipeline.length !== 1 ? 's' : ''} on the team · runs in sandbox
            </span>
          )}
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>

          {/* ── Phase 2: Navigate — the route emerges (compass mode) ── */}
          {govMode === 'compass' && pipeline.length >= 2 && (() => {
            const routeContent = pipeline.map(n => n.content).join('\n').trim();
            const head = contentHeading(routeContent);
            const planned = planRoute(pipeline, routeContent, instincts);
            const sameOrder = planned.every((p, i) => p.agent.id === pipeline[i].id);
            const learned = !!instincts?.learned;
            return (
              <div style={{ border: '2px solid #0088aa', background: 'var(--surface)', boxShadow: '2px 2px 0 var(--chrome-dd)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', borderBottom: '1px solid var(--chrome-dd)', background: 'var(--surface-2)' }}>
                  <Compass size={14} style={{ color: '#0088aa' }} />
                  <span style={{ fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700, color: 'var(--text)' }}>Navigate — let the route emerge</span>
                  <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>compass mode</span>
                </div>
                <div style={{ padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {head.length === 0 ? (
                    <div style={{ fontFamily: 'var(--font-ui)', fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.4 }}>
                      Drop a file or paste content into an agent, and I'll order the party by where the file's risk points — strongest-risk first.
                    </div>
                  ) : (
                    <>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
                        <span style={{ fontFamily: 'var(--font-ui)', fontSize: 11, color: 'var(--text-muted)' }}>File points toward:</span>
                        {head.slice(0, 4).map(h => { const m = TYPE_LABEL[h.key]; return (
                          <span key={h.key} style={{ fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 700, color: m?.color }}>{m?.emoji} {m?.label} {(h.score * 100).toFixed(0)}%</span>
                        ); })}
                      </div>
                      {learned && (
                        <Tooltip tip={`Instinct is distilled from your last ${instincts!.totalRuns} runs.\nTypes that found risk before get a small nudge to lead ties —\nit can never outrank the file's concrete signal, only break a tie within it.`}>
                          <div style={{ fontFamily: 'var(--font-ui)', fontSize: 10.5, color: '#7a5cff', cursor: 'help', display: 'flex', alignItems: 'center', gap: 5 }}>
                            <span>🦋</span>
                            <span><strong>Instinct</strong> — learned from {instincts!.totalRuns} past run{instincts!.totalRuns !== 1 ? 's' : ''}; proven finders break ties.</span>
                          </div>
                        </Tooltip>
                      )}
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {planned.map((p, i) => { const t = TYPE_LABEL[p.typeKey]; const showInstinct = learned && p.instinct !== 0.5 && !!p.instinctNote; return (
                          <div key={p.agent.id} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, color: '#0088aa', width: 14, flexShrink: 0 }}>{i + 1}</span>
                            <Creature seed={p.agent.seed} color={t?.color ?? '#888'} size={18} />
                            <span style={{ fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700, color: 'var(--text)', flexShrink: 0 }}>{p.agent.name}</span>
                            <div style={{ width: 90, height: 5, background: 'var(--paper-3)', flexShrink: 0 }}>
                              <div style={{ width: `${p.affinity * 100}%`, height: '100%', background: t?.color ?? '#888' }} />
                            </div>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {p.affinity > 0 ? `matched: ${p.matched}` : 'no signal · runs last'}
                            </span>
                            {showInstinct && (
                              <Tooltip tip={`Instinct: ${p.instinctNote}`}>
                                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: p.instinct > 0.5 ? '#7a5cff' : 'var(--text-muted)', flexShrink: 0, cursor: 'help' }}>
                                  🦋 {p.instinct > 0.5 ? 'proven' : 'quiet'}
                                </span>
                              </Tooltip>
                            )}
                          </div>
                        ); })}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.4, flex: 1, minWidth: 180 }}>
                          {learned
                            ? 'Apply sets this static order; Run live lets the route re-pick after each finding. Both run through the same gate.'
                            : 'Apply sets this static order; Run live lets the route re-pick after each finding. Both run through the same gate.'}
                        </span>
                        <button
                          onClick={() => applyRoute(planned.map(p => p.agent))}
                          disabled={sameOrder || isActive}
                          style={{
                            flexShrink: 0, padding: '6px 12px',
                            background: sameOrder || isActive ? 'var(--surface-2)' : 'linear-gradient(to right, #006677, #0088aa)',
                            color: sameOrder || isActive ? 'var(--text-muted)' : '#fff', border: 'var(--bw)',
                            cursor: sameOrder || isActive ? 'default' : 'pointer', fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 700,
                          }}
                        >
                          {sameOrder ? '✓ already on route' : '↳ Apply this order'}
                        </button>
                        <Tooltip tip={'Run the party live: pick the strongest agent, run it (gated, sandboxed),\nread what it found, then re-pick the next from the real result.\nThe route adapts to where the risk actually is.'}>
                          <button
                            onClick={() => runLive(true)}
                            disabled={!sessionId || isActive}
                            style={{
                              flexShrink: 0, padding: '6px 12px', display: 'inline-flex', alignItems: 'center', gap: 5,
                              background: !sessionId || isActive ? 'var(--surface-2)' : 'linear-gradient(to right, #6a3fd6, #8a5cff)',
                              color: !sessionId || isActive ? 'var(--text-muted)' : '#fff', border: 'var(--bw)',
                              cursor: !sessionId || isActive ? 'default' : 'pointer', fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 700,
                            }}
                          >
                            {liveStatus === 'running' ? '◇ descending…' : '◆ Run live'}
                          </button>
                        </Tooltip>
                      </div>
                    </>
                  )}
                </div>
              </div>
            );
          })()}

          {/* ── Phase 4: Live descent — the route emerges as it runs ── */}
          {liveSteps.length > 0 && (() => {
            const done = liveSteps.filter(s => s.status === 'done');
            const foundCount = done.filter(s => (s.risk ?? 0) >= 50 || s.found.length > 0).length;
            const peak = done.reduce((m, s) => Math.max(m, s.risk ?? 0), 0);
            return (
              <div style={{ border: '2px solid #8a5cff', background: 'var(--surface)', boxShadow: '2px 2px 0 var(--chrome-dd)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', borderBottom: '1px solid var(--chrome-dd)', background: 'var(--surface-2)' }}>
                  {govMode === 'compass'
                    ? <Compass size={14} style={{ color: '#8a5cff' }} className={liveStatus === 'running' ? 'spin' : ''} />
                    : <Play size={14} style={{ color: '#8a5cff' }} className={liveStatus === 'running' ? 'spin' : ''} />}
                  <span style={{ fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700, color: 'var(--text)' }}>
                    {govMode === 'compass' ? 'Live descent — the route emerges as it runs' : 'Live run — your party, one agent at a time'}
                  </span>
                  <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
                    {liveStatus === 'running' ? `step ${liveSteps.length}/${pipeline.length}…` : `${done.length} ran`}
                  </span>
                </div>
                <div style={{ padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 5 }}>
                  {liveSteps.map((s, i) => {
                    const t = TYPE_LABEL[s.typeKey];
                    const r = s.risk ?? 0;
                    const rc = r >= 80 ? '#cc2200' : r >= 50 ? '#e07000' : r > 0 ? '#c9a200' : '#2a9d4a';
                    return (
                      <div key={s.nodeId} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, color: '#8a5cff', width: 14, flexShrink: 0 }}>{i + 1}</span>
                        <Creature seed={s.seed} color={t?.color ?? '#888'} size={18} />
                        <span style={{ fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700, color: 'var(--text)', flexShrink: 0 }}>{s.name}</span>
                        {s.status === 'running' && <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#8a5cff' }}>◇ running…</span>}
                        {s.status === 'done' && (
                          <span className="chip" style={{ background: rc + '22', borderColor: rc, color: rc, fontSize: 10 }}>
                            risk {r.toFixed(0)}{r >= 50 ? ' 🔥' : ''}
                          </span>
                        )}
                        {s.status === 'blocked' && <span className="chip chip-yellow" style={{ fontSize: 10 }}>gate blocked</span>}
                        {s.status === 'error' && <span className="chip chip-red" style={{ fontSize: 10 }}>error</span>}
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {s.detail
                            ? s.detail
                            : s.found.length > 0
                              ? `found: ${s.found[0]}`
                              : s.status === 'done'
                                ? 'clean'
                                : s.reason}
                        </span>
                      </div>
                    );
                  })}
                  {liveStatus === 'done' && (
                    <div style={{ marginTop: 4, paddingTop: 8, borderTop: '1px dashed var(--paper-3)', fontFamily: 'var(--font-ui)', fontSize: 11, color: 'var(--text)' }}>
                      Route complete — ran {done.length} agent{done.length !== 1 ? 's' : ''},
                      {' '}<strong style={{ color: foundCount > 0 ? '#cc2200' : '#2a9d4a' }}>{foundCount} found risk</strong>
                      {peak > 0 ? `, peak ${peak.toFixed(0)}` : ''}. Each run is hash-chained in the Battle Log.
                      <button className="btn btn-sm" onClick={reset} style={{ marginLeft: 10 }}>Clear</button>
                    </div>
                  )}
                </div>
              </div>
            );
          })()}

          {/* Empty state — starter parties */}
          {pipeline.length === 0 && (
            <div>
              <div style={{
                fontFamily: 'var(--font-ui)', fontSize: 13, fontWeight: 700, color: 'var(--text)', marginBottom: 4,
              }}>
                Start with a ready-made party
              </div>
              <div style={{ fontFamily: 'var(--font-ui)', fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>
                One click picks a proven team — or pick agents yourself on the left.
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(190px, 1fr))', gap: 10 }}>
                {PLAYBOOKS.map(pb => {
                  const found = pb.picks.filter(pat => agents.some(c => (c.agent_name || '').toLowerCase().includes(pat.toLowerCase()))).length;
                  return (
                    <button
                      key={pb.key}
                      onClick={() => loadPlaybook(pb)}
                      disabled={agentsLoading || found === 0}
                      style={{
                        textAlign: 'left', cursor: found ? 'pointer' : 'default',
                        padding: '10px 12px', background: 'var(--surface)',
                        border: `2px solid ${pb.color}`, borderLeft: `5px solid ${pb.color}`,
                        display: 'flex', flexDirection: 'column', gap: 4, opacity: found ? 1 : 0.5,
                        transition: 'transform 80ms, box-shadow 80ms',
                      }}
                      onMouseEnter={e => { e.currentTarget.style.boxShadow = `0 0 12px ${pb.color}66`; e.currentTarget.style.transform = 'translateY(-1px)'; }}
                      onMouseLeave={e => { e.currentTarget.style.boxShadow = 'none'; e.currentTarget.style.transform = 'none'; }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                        <span style={{ fontSize: 18 }}>{pb.emoji}</span>
                        <span style={{ fontFamily: 'var(--font-ui)', fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>{pb.name}</span>
                        <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, color: pb.color }}>×{found}</span>
                      </div>
                      <div style={{ fontFamily: 'var(--font-ui)', fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.35 }}>{pb.desc}</div>
                    </button>
                  );
                })}
              </div>

              <div style={{
                marginTop: 16, padding: '10px 14px', textAlign: 'center',
                border: '1px dashed var(--chrome-dd)',
                fontFamily: 'var(--font-ui)', fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.6,
              }}>
                Each agent then takes a file/paste to scan; hit Simulate, then Run.
              </div>
            </div>
          )}

          {/* Pipeline nodes */}
          {pipeline.map((node, i) => {
            const type = agentTypeOf(node.seed, node.tags);
            return (
            <div key={node.id}>
              {/* Node card */}
              <div style={{
                border: '1px solid var(--chrome-dd)',
                borderTop: `3px solid ${type.color}`,
                background: 'var(--surface)',
                boxShadow: '1px 1px 0 var(--chrome-dd)',
              }}>
                {/* Node header */}
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '5px 10px',
                  background: 'var(--surface-2)', borderBottom: '1px solid var(--chrome-dd)',
                }}>
                  <span style={{
                    background: type.color, color: '#fff',
                    fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700,
                    padding: '1px 6px', flexShrink: 0,
                  }}>
                    {i + 1}
                  </span>
                  <Creature seed={node.seed} color={type.color} size={22} />
                  <span style={{ fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700, color: 'var(--text)' }}>
                    {node.name}
                  </span>
                  <div style={{ display: 'flex', gap: 3, flex: 1, flexWrap: 'wrap' }}>
                    {node.tags.slice(0, 2).map(t => (
                      <span key={t} style={{
                        fontFamily: 'var(--font-mono)', fontSize: 11,
                        background: '#d8ecd8', color: '#1a6633',
                        padding: '1px 5px', border: '1px solid #b8d8b8',
                      }}>
                        {t}
                      </span>
                    ))}
                  </div>
                  <button
                    onClick={() => removeNode(node.id)}
                    disabled={isActive}
                    style={{
                      marginLeft: 'auto', background: 'none', border: 'none',
                      cursor: isActive ? 'default' : 'pointer',
                      color: isActive ? '#ccc' : '#cc0022', padding: 2, flexShrink: 0,
                    }}
                  >
                    <X size={12} />
                  </button>
                </div>

                {/* Goal input */}
                <div style={{ padding: '8px 10px' }}>
                  <Tooltip tip={`The goal text is keyword-dispatched to ${node.name}.\nEdit it to match one of the agent's keywords:\n${node.tags.map(t => `· ${t}`).join('\n')}`}>
                    <div style={{
                      fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 600,
                      textTransform: 'uppercase', letterSpacing: '0.06em',
                      color: 'var(--text)', marginBottom: 4, cursor: 'help',
                    }}>
                      Goal — routes to this agent (?)
                    </div>
                  </Tooltip>
                  <input
                    className="input"
                    style={{ width: '100%' }}
                    value={node.goal}
                    onChange={e => updateGoal(node.id, e.target.value)}
                    disabled={isActive}
                    placeholder={node.tags[0] ?? 'enter goal keywords…'}
                  />
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text)', marginTop: 3 }}>
                    {node.capId} · SANDBOX
                  </div>

                  {/* Content to scan — pick a file or paste */}
                  <div style={{ marginTop: 10 }}>
                    <div style={{
                      display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4,
                    }}>
                      <span style={{
                        fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 600,
                        textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text)',
                      }}>
                        Content to scan
                      </span>
                      <label className="btn btn-sm" style={{ cursor: isActive ? 'default' : 'pointer', flexShrink: 0 }}>
                        <FileUp size={11} style={{ marginRight: 4 }} />
                        Pick file
                        <input
                          type="file"
                          style={{ display: 'none' }}
                          disabled={isActive}
                          onChange={e => { const f = e.target.files?.[0]; if (f) readFileIntoNode(node.id, f); e.currentTarget.value = ''; }}
                        />
                      </label>
                      {node.filename && (
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {node.filename} · {node.content.length} chars
                        </span>
                      )}
                    </div>
                    <textarea
                      className="input"
                      style={{ width: '100%', minHeight: 72, resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: 11, boxSizing: 'border-box' }}
                      value={node.content}
                      onChange={e => updateNode(node.id, { content: e.target.value })}
                      disabled={isActive}
                      placeholder="Paste code/config/text to scan, or drop a file above. Leave empty for a dry structural run."
                      onDragOver={e => e.preventDefault()}
                      onDrop={e => { e.preventDefault(); const f = e.dataTransfer.files?.[0]; if (f && !isActive) readFileIntoNode(node.id, f); }}
                    />
                  </div>
                </div>
              </div>

              {/* Connector arrow */}
              {i < pipeline.length - 1 && (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '2px 0', color: 'var(--text)' }}>
                  <ChevronRight size={16} />
                </div>
              )}
            </div>
            );
          })}

          {/* Error */}
          {error && (
            <div style={{
              border: '1px solid var(--red)', background: '#ffe0e6',
              padding: '10px 14px', color: 'var(--red)',
              fontFamily: 'var(--font-mono)', fontSize: 12,
            }}>
              {error}
            </div>
          )}

          {/* Action buttons */}
          {(phase === 'configure' || phase === 'review') && pipeline.length > 0 && liveStatus !== 'running' && (
            <div style={{ display: 'flex', gap: 8, marginTop: 4, alignItems: 'center' }}>
              <Tooltip tip={'Run the whole party LIVE — each agent runs in a sandbox, one at a time,\nand you watch its result (risk + findings) appear as it goes.\nNo dry-run needed.'}>
                <button
                  className="btn btn-green"
                  onClick={() => runLive(govMode === 'compass')}
                  disabled={!sessionId}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6, fontWeight: 700,
                    opacity: !sessionId ? 0.4 : 1,
                  }}
                >
                  <Play size={13} /> Run live · {pipeline.length} agent{pipeline.length !== 1 ? 's' : ''}
                </button>
              </Tooltip>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>or</span>
              <Tooltip tip="Dry-run only: validates the DAG, policy, risk, and bounds.\nNo agents are called.">
                <button
                  className="btn btn-sm"
                  onClick={simulate}
                  disabled={!sessionId}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    opacity: !sessionId ? 0.4 : 1,
                  }}
                >
                  Simulate (dry-run)
                </button>
              </Tooltip>
              {phase === 'review' && canExec && (
                <Tooltip tip="Execute the pipeline. Each agent runs in a SANDBOX via pi-extension-governor.\nResults are hash-chained into the Ledger with a full audit trail.">
                  <button
                    className="btn btn-green"
                    onClick={run}
                    style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                  >
                    <Send size={13} /> Approve & Run
                  </button>
                </Tooltip>
              )}
              {phase === 'review' && (
                <button className="btn btn-sm" onClick={reset} style={{ marginLeft: 'auto' }}>
                  Reset
                </button>
              )}
            </div>
          )}

          {/* Status spinners */}
          {phase === 'simulating' && (
            <div style={{ fontFamily: 'var(--font-ui)', fontSize: 13, color: 'var(--text)', padding: '12px 0' }}>
              Simulating pipeline…
            </div>
          )}
          {phase === 'running' && (
            <div style={{ fontFamily: 'var(--font-ui)', fontSize: 13, color: 'var(--text)', padding: '12px 0' }}>
              Executing pipeline…
            </div>
          )}

          {/* Done banner */}
          {phase === 'done' && ledgerId && (
            <div style={{ border: '1px solid var(--green)', background: '#d4f5e5', padding: '12px 16px' }}>
              <div style={{ fontFamily: 'var(--font-ui)', fontSize: 13, fontWeight: 700, color: '#004400' }}>
                ✓ Pipeline executed successfully
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#226633', marginTop: 4 }}>
                Ledger: {ledgerId}
              </div>
              <div style={{ fontFamily: 'var(--font-ui)', fontSize: 12, color: 'var(--text)', marginTop: 4 }}>
                Open the Ledger tab to see the full hash-chained audit trace.
              </div>
              <button className="btn btn-sm" onClick={reset} style={{ marginTop: 8 }}>Run another</button>
            </div>
          )}

          {/* Simulation report */}
          {report && (phase === 'review' || phase === 'done') && (
            <SimReport report={report} />
          )}

        </div>
      </div>
    </div>
  );
}

// ─── SimReport ────────────────────────────────────────────────────────────────

function SimReport({ report }: { report: SimulationReport }) {
  const riskColor = RISK_COLOR[report.risk_level] ?? '#555';
  const issues = [
    ...report.dag_errors,
    ...report.bounds_violations,
    ...report.policy_violations,
    ...report.risk_details,
  ];

  return (
    <div style={{ marginTop: 8, borderTop: '1px solid var(--chrome-dd)', paddingTop: 14 }}>
      <div style={{
        fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700,
        textTransform: 'uppercase', letterSpacing: '0.07em', color: 'var(--text)', marginBottom: 10,
      }}>
        Simulation Results
      </div>

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
        <span className={`chip ${report.dag_valid ? 'chip-green' : 'chip-red'}`}>
          {report.dag_valid
            ? <CheckCircle2 size={10} style={{ marginRight: 3 }} />
            : <XCircle size={10} style={{ marginRight: 3 }} />}
          DAG {report.dag_valid ? 'valid' : 'invalid'}
        </span>
        <Tooltip tip="CRITICAL/HIGH = execution blocked · MEDIUM = warning · LOW/NONE = safe to run">
          <span className="chip" style={{ background: riskColor + '22', borderColor: riskColor, color: riskColor }}>
            <AlertTriangle size={10} style={{ marginRight: 3 }} />
            {report.risk_level} risk
          </span>
        </Tooltip>
        <span className={`chip ${report.bounds_respected ? 'chip-green' : 'chip-red'}`}>
          Bounds {report.bounds_respected ? 'OK' : 'violated'}
        </span>
        <span className={`chip ${report.replay_safe ? 'chip-green' : 'chip-yellow'}`}>
          Replay {report.replay_safe ? 'safe' : 'unsafe'}
        </span>
      </div>

      {issues.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 12 }}>
          {issues.map((msg, idx) => (
            <div key={idx} style={{
              padding: '7px 12px', background: '#fff5e6',
              border: '1px solid #cc6600', color: '#7a3300',
              fontFamily: 'var(--font-ui)', fontSize: 12,
            }}>
              ⚠ {msg}
            </div>
          ))}
        </div>
      )}

      {report.execution_plan?.length > 0 && (
        <div>
          <div style={{
            fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700,
            textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text)', marginBottom: 6,
          }}>
            Execution Plan
          </div>
          {report.execution_plan.map((step, idx) => (
            <div key={idx} style={{
              display: 'flex', gap: 10, padding: '6px 0',
              borderBottom: '1px solid var(--paper-3)',
              fontFamily: 'var(--font-ui)', fontSize: 12, color: 'var(--text)',
            }}>
              <span style={{
                width: 20, height: 20, background: '#006677', color: '#fff',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontFamily: 'var(--font-mono)', fontSize: 12, flexShrink: 0,
              }}>
                {idx + 1}
              </span>
              {step}
            </div>
          ))}
        </div>
      )}

      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text)', marginTop: 10, wordBreak: 'break-all' }}>
        {report.report_hash}
      </div>
    </div>
  );
}
