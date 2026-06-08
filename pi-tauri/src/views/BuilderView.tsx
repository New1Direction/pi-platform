import { useState, useEffect } from 'react';
import { Search, Play, Send, AlertTriangle, CheckCircle2, XCircle, ChevronRight, X } from 'lucide-react';
import { listAllCapabilities, simulateComposition, submitComposition, getTenantId } from '../lib/api';
import type { MarketplaceCapability, SimulationReport } from '../types';
import { Tooltip } from '../components/Tooltip';

// ─── Types ────────────────────────────────────────────────────────────────────

type PipelineNode = {
  id: string;
  capId: string;
  name: string;
  tags: string[];
  goal: string;
};

type Phase = 'configure' | 'simulating' | 'review' | 'running' | 'done';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function agentName(cap: MarketplaceCapability): string {
  const sep = cap.description.indexOf(' — ');
  return sep > 0 ? cap.description.slice(0, sep) : cap.capability_id.replace('cap_', '');
}

const TIER_COLOR: Record<string, string> = {
  GOVERNED: '#1a6633',
  AUDITED: '#005c88',
  VERIFIED: '#884400',
  UNVERIFIED: '#666',
};

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
      artifacts: [{ goal: n.goal }],
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

// ─── AgentCard ────────────────────────────────────────────────────────────────

function AgentCard({ cap, onAdd }: { cap: MarketplaceCapability; onAdd: (c: MarketplaceCapability) => void }) {
  const name = agentName(cap);
  const tags = cap.compatibility_tags.slice(0, 3);
  const tipText = `${name}\n\nKeywords:\n${cap.compatibility_tags.map(t => `· ${t}`).join('\n')}\n\nTrust tier: ${cap.trust_tier}\n\nClick to add to pipeline.`;

  return (
    <Tooltip tip={tipText} pos="right" wrapStyle={{ display: 'block' }}>
      <button
        onClick={() => onAdd(cap)}
        style={{
          display: 'flex', flexDirection: 'column', gap: 4,
          padding: '7px 10px', width: '100%', textAlign: 'left',
          background: 'transparent', border: 'none',
          borderBottom: '1px solid var(--chrome-dd)',
          cursor: 'pointer', transition: 'background 60ms',
        }}
        onMouseEnter={e => (e.currentTarget.style.background = '#e4e4e4')}
        onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <span style={{
            fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700, color: '#111',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1,
          }}>
            {name}
          </span>
          <span style={{
            fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700,
            background: TIER_COLOR[cap.trust_tier] ?? '#555', color: '#fff',
            padding: '1px 4px', flexShrink: 0,
          }}>
            {cap.trust_tier}
          </span>
        </div>
        <div style={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
          {tags.map(t => (
            <span key={t} style={{
              fontFamily: 'var(--font-mono)', fontSize: 11, color: '#444',
              background: '#e0e0e0', padding: '1px 4px',
            }}>
              {t}
            </span>
          ))}
        </div>
      </button>
    </Tooltip>
  );
}

// ─── BuilderView ──────────────────────────────────────────────────────────────

export function BuilderView({ sessionId }: { sessionId: string | null }) {
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
    setPipeline(prev => {
      const idx = prev.length;
      return [...prev, {
        id: `n${idx + 1}`,
        capId: cap.capability_id,
        name: agentName(cap),
        tags: cap.compatibility_tags,
        goal: cap.compatibility_tags[0] ?? '',
      }];
    });
    setPhase('configure');
    setReport(null);
    setError(null);
  };

  const removeNode = (id: string) =>
    setPipeline(prev =>
      prev.filter(n => n.id !== id).map((n, i) => ({ ...n, id: `n${i + 1}` }))
    );

  const updateGoal = (id: string, goal: string) =>
    setPipeline(prev => prev.map(n => n.id === id ? { ...n, goal } : n));

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

  const reset = () => {
    setPhase('configure'); setReport(null); setLedgerId(null); setError(null);
  };

  const isActive = phase === 'simulating' || phase === 'running';

  return (
    <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

      {/* ── Agent Browser ──────────────────────────────────────────── */}
      <div style={{
        width: 224, flexShrink: 0, borderRight: '1px solid var(--chrome-dd)',
        display: 'flex', flexDirection: 'column', background: '#f4f4f4',
      }}>

        {/* Panel header */}
        <div style={{
          padding: '8px 10px', background: 'var(--chrome)',
          borderBottom: '1px solid var(--chrome-dd)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span style={{ fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Agent Registry
          </span>
          <button
            onClick={loadAgents}
            disabled={agentsLoading}
            style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#2a2a2a', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
            title="Reload agent list"
          >
            {agentsLoading ? '…' : `↺ ${agents.length}`}
          </button>
        </div>

        {/* Search bar */}
        <div style={{ padding: '6px 8px', borderBottom: '1px solid var(--chrome-dd)', background: 'var(--chrome)' }}>
          <div style={{
            display: 'flex', alignItems: 'center',
            border: 'var(--bw)', background: '#fff',
            boxShadow: 'inset 1px 1px 0 var(--chrome-dd)',
          }}>
            <Search size={11} style={{ margin: '0 6px', color: '#2a2a2a', flexShrink: 0 }} />
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
            <div style={{ padding: 16, fontFamily: 'var(--font-mono)', fontSize: 12, color: '#2a2a2a', textAlign: 'center' }}>
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
            <div style={{ padding: 16, fontFamily: 'var(--font-mono)', fontSize: 12, color: '#2a2a2a', textAlign: 'center' }}>
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
          fontFamily: 'var(--font-ui)', fontSize: 12, color: '#2a2a2a',
          background: 'var(--chrome)', lineHeight: 1.5,
        }}>
          Click any agent to add it to the pipeline. Hover for keywords.
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
            Pipeline Canvas
          </span>
          {pipeline.length > 0 && (
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#2a2a2a' }}>
              {pipeline.length} node{pipeline.length !== 1 ? 's' : ''} · all via pi-extension-governor · SANDBOX
            </span>
          )}
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>

          {/* Empty state */}
          {pipeline.length === 0 && (
            <div style={{
              padding: '36px 28px', textAlign: 'center',
              border: '1px dashed var(--chrome-dd)',
              fontFamily: 'var(--font-ui)', fontSize: 12, color: '#2a2a2a',
              lineHeight: 1.8,
            }}>
              Browse the registry on the left and click any agent to add it here.
              <div style={{ marginTop: 8, fontSize: 12, color: '#2a2a2a' }}>
                Each agent is identified by the keywords in its goal text.<br />
                The router dispatches the goal to the matching agent automatically.
              </div>
            </div>
          )}

          {/* Pipeline nodes */}
          {pipeline.map((node, i) => (
            <div key={node.id}>
              {/* Node card */}
              <div style={{
                border: '1px solid var(--chrome-dd)',
                borderTop: '3px solid #006677',
                background: '#fff',
                boxShadow: '1px 1px 0 var(--chrome-dd)',
              }}>
                {/* Node header */}
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '5px 10px',
                  background: '#f0f0f0', borderBottom: '1px solid var(--chrome-dd)',
                }}>
                  <span style={{
                    background: '#006677', color: '#fff',
                    fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700,
                    padding: '1px 6px', flexShrink: 0,
                  }}>
                    N{i + 1}
                  </span>
                  <span style={{ fontFamily: 'var(--font-ui)', fontSize: 12, fontWeight: 700, color: '#111' }}>
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
                      color: '#2a2a2a', marginBottom: 4, cursor: 'help',
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
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#2a2a2a', marginTop: 3 }}>
                    {node.capId} · SANDBOX
                  </div>
                </div>
              </div>

              {/* Connector arrow */}
              {i < pipeline.length - 1 && (
                <div style={{ display: 'flex', justifyContent: 'center', padding: '2px 0', color: '#2a2a2a' }}>
                  <ChevronRight size={16} />
                </div>
              )}
            </div>
          ))}

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
          {(phase === 'configure' || phase === 'review') && pipeline.length > 0 && (
            <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
              <Tooltip tip="Dry-run the pipeline. Validates the DAG, checks policy, risk, and bounds.\nNo agents are called.">
                <button
                  className="btn"
                  onClick={simulate}
                  disabled={!sessionId}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    opacity: !sessionId ? 0.4 : 1,
                  }}
                >
                  <Play size={13} /> Simulate
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
            <div style={{ fontFamily: 'var(--font-ui)', fontSize: 13, color: '#2a2a2a', padding: '12px 0' }}>
              Simulating pipeline…
            </div>
          )}
          {phase === 'running' && (
            <div style={{ fontFamily: 'var(--font-ui)', fontSize: 13, color: '#2a2a2a', padding: '12px 0' }}>
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
              <div style={{ fontFamily: 'var(--font-ui)', fontSize: 12, color: '#2a2a2a', marginTop: 4 }}>
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
        textTransform: 'uppercase', letterSpacing: '0.07em', color: '#2a2a2a', marginBottom: 10,
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
            textTransform: 'uppercase', letterSpacing: '0.06em', color: '#2a2a2a', marginBottom: 6,
          }}>
            Execution Plan
          </div>
          {report.execution_plan.map((step, idx) => (
            <div key={idx} style={{
              display: 'flex', gap: 10, padding: '6px 0',
              borderBottom: '1px solid #eee',
              fontFamily: 'var(--font-ui)', fontSize: 12, color: '#222',
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

      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#2a2a2a', marginTop: 10, wordBreak: 'break-all' }}>
        {report.report_hash}
      </div>
    </div>
  );
}
