import { useState } from 'react';
import { Plus, Play, CheckCircle2, XCircle, AlertTriangle, Send } from 'lucide-react';
import { Tooltip } from '../components/Tooltip';
import { simulateComposition, submitComposition } from '../lib/api';
import type { SimulationReport } from '../types';

type NodeDraft = { id: string; runtime: string; operation: string; goal: string };

const RUNTIMES = ['pi-extension-governor', 'pi-semantic-recon', 'pi-semantic-validator', 'pi-semantic-diff', 'pi-blast-radius'];
const OPERATIONS = ['SANDBOX', 'VALIDATE', 'DIFF', 'BLAST_RADIUS', 'AUDIT', 'CLASSIFY', 'POLICY_GATE', 'COMPOSE'];

const RISK_COLOR: Record<string, string> = {
  NONE: 'chip-green', LOW: 'chip-green', MEDIUM: 'chip-yellow', HIGH: 'chip-red', CRITICAL: 'chip-red',
};

function buildRequest(nodes: NodeDraft[], sessionId: string) {
  return {
    request_id: crypto.randomUUID(),
    tenant_id: 'default',
    console_session_id: sessionId,
    created_at: new Date().toISOString(),
    nodes: nodes.map(n => ({
      node_id: n.id,
      runtime: n.runtime,
      operation: n.operation,
      artifacts: [{ goal: n.goal }],
      required_schema_version: '1.0.0',
      bounds: { max_depth: 3, max_fanout: 4 },
      dependencies: [],
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

export function ComposeView({ sessionId }: { sessionId: string | null }) {
  const [nodes, setNodes] = useState<NodeDraft[]>([
    { id: 'n1', runtime: 'pi-extension-governor', operation: 'SANDBOX', goal: '' },
  ]);
  const [report, setReport] = useState<SimulationReport | null>(null);
  const [canExecute, setCanExecute] = useState(false);
  const [loading, setLoading] = useState(false);
  const [submitLoading, setSubmitLoading] = useState(false);
  const [ledgerId, setLedgerId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const addNode = () => setNodes(n => [...n, { id: `n${n.length + 1}`, runtime: 'pi-extension-governor', operation: 'SANDBOX', goal: '' }]);
  const removeNode = (id: string) => setNodes(n => n.filter(x => x.id !== id));
  const updateNode = (id: string, field: keyof NodeDraft, value: string) =>
    setNodes(n => n.map(x => x.id === id ? { ...x, [field]: value } : x));

  const simulate = async () => {
    if (!sessionId) return;
    setLoading(true); setError(null); setReport(null); setLedgerId(null);
    try {
      const req = buildRequest(nodes, sessionId);
      const r = await simulateComposition(req);
      setReport(r.report); setCanExecute(r.can_execute);
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const submit = async () => {
    if (!sessionId || !canExecute) return;
    setSubmitLoading(true); setError(null);
    try {
      const req = { ...buildRequest(nodes, sessionId), approved_by_user: true };
      const r = await submitComposition(req) as { core_ledger_id?: string };
      setLedgerId(r.core_ledger_id ?? null);
    } catch (e) { setError(String(e)); }
    finally { setSubmitLoading(false); }
  };

  return (
    <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

      {/* ── Left: node builder ── */}
      <div style={{ flex: '0 0 480px', borderRight: 'var(--bw)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

        <div className="win-title compose">
          
          COMPOSITION BUILDER
          <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 12, opacity: 0.7 }}>
            {nodes.length} node{nodes.length !== 1 ? 's' : ''}
          </span>
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: 12, display: 'flex', flexDirection: 'column', gap: 10 }}>
          {nodes.map((n, i) => (
            <div key={n.id} style={{ border: 'var(--bw)', boxShadow: 'var(--shadow-sm)', background: 'var(--white)' }}>
              {/* Node header */}
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '6px 10px', borderBottom: '1px solid var(--paper-3)',
                background: 'var(--paper-2)',
              }}>
                <span style={{
                  background: 'var(--ink)', color: 'var(--yellow)',
                  fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700,
                  padding: '1px 7px',
                }}>{n.id.toUpperCase()}</span>
                {i > 0 && (
                  <button className="btn btn-sm" onClick={() => removeNode(n.id)}
                    style={{ marginLeft: 'auto', color: 'var(--red)', borderColor: 'var(--red)', padding: '1px 8px', fontSize: 10 }}>
                    REMOVE
                  </button>
                )}
              </div>

              {/* Fields */}
              <div style={{ padding: 10, display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ display: 'flex', gap: 8 }}>
                  <div style={{ flex: 1 }}>
                    <Tooltip tip={'Runtime selects the execution environment:\n· extension-governor — general agent sandbox\n· semantic-validator — schema/spec checking\n· semantic-diff — version comparison\n· blast-radius — impact analysis\n· semantic-recon — threat reconnaissance'}>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4, color: '#2a2a2a', cursor: 'help' }}>RUNTIME (?)</div>
                    </Tooltip>
                    <select className="input" value={n.runtime} onChange={e => updateNode(n.id, 'runtime', e.target.value)}
                      style={{ width: '100%' }}>
                      {RUNTIMES.map(r => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </div>
                  <div style={{ flex: '0 0 130px' }}>
                    <Tooltip tip={'Operation type:\n· SANDBOX — isolated safe execution\n· SCAN — find issues or threats\n· VALIDATE — correctness check\n· DIFF — compare two versions\n· ANALYZE — deep inspection'}>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4, color: '#2a2a2a', cursor: 'help' }}>OPERATION (?)</div>
                    </Tooltip>
                    <select className="input" value={n.operation} onChange={e => updateNode(n.id, 'operation', e.target.value)}
                      style={{ width: '100%' }}>
                      {OPERATIONS.map(o => <option key={o}>{o}</option>)}
                    </select>
                  </div>
                </div>
                <div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4, color: '#2a2a2a' }}>GOAL / ARTIFACT</div>
                  <input className="input" style={{ width: '100%' }}
                    placeholder="e.g. scan for reentrancy vulnerabilities"
                    value={n.goal} onChange={e => updateNode(n.id, 'goal', e.target.value)} />
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Actions */}
        <div style={{ padding: 12, borderTop: 'var(--bw)', display: 'flex', gap: 8 }}>
          <Tooltip tip="Add another agent node to the composition.\nNodes run as a DAG — you can chain them.">
            <button className="btn btn-sm" onClick={addNode} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <Plus size={12} /> ADD NODE
            </button>
          </Tooltip>
          <Tooltip tip="Dry-run the composition without executing.\nChecks DAG validity, risk level, bounds, and policy.\nNo agents are actually called." wrapStyle={{ flex: 1 }}>
            <button className="btn btn-ink" onClick={simulate} disabled={loading || !sessionId}
              style={{ display: 'flex', alignItems: 'center', gap: 6, width: '100%', justifyContent: 'center', opacity: !sessionId ? 0.4 : 1 }}>
              <Play size={13} /> {loading ? 'SIMULATING…' : 'SIMULATE'}
            </button>
          </Tooltip>
        </div>
      </div>

      {/* ── Right: simulation result ── */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div className="win-title compose">
          
          SIMULATION REPORT
        </div>

        <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
          {error && (
            <div style={{ border: '2px solid var(--red)', padding: 12, background: '#ffd8d0', marginBottom: 12, fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--red)' }}>
              {error}
            </div>
          )}

          {!report && !error && !loading && (
            <div style={{ textAlign: 'center', padding: 48, fontFamily: 'var(--font-mono)', fontSize: 12, color: '#2a2a2a' }}>
              configure nodes and click SIMULATE
            </div>
          )}

          {loading && (
            <div style={{ textAlign: 'center', padding: 48, fontFamily: 'var(--font-mono)', fontSize: 12, color: '#2a2a2a' }}>
              simulating…
            </div>
          )}

          {ledgerId && (
            <div style={{ border: '2px solid var(--green)', padding: 12, background: '#c8ffd8', marginBottom: 16, fontFamily: 'var(--font-mono)', fontSize: 11 }}>
              <CheckCircle2 size={14} style={{ color: 'var(--green)', marginRight: 8, display: 'inline' }} />
              SUBMITTED · ledger: {ledgerId}
            </div>
          )}

          {report && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

              {/* Status row */}
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <span className={`chip ${report.dag_valid ? 'chip-green' : 'chip-red'}`}>
                  {report.dag_valid ? <CheckCircle2 size={10} style={{ marginRight: 4 }} /> : <XCircle size={10} style={{ marginRight: 4 }} />}
                  DAG {report.dag_valid ? 'VALID' : 'INVALID'}
                </span>
                <span className={`chip ${RISK_COLOR[report.risk_level] ?? 'chip-ink'}`}>
                  <AlertTriangle size={10} style={{ marginRight: 4 }} />
                  RISK: {report.risk_level}
                </span>
                <span className={`chip ${report.replay_safe ? 'chip-green' : 'chip-yellow'}`}>
                  REPLAY SAFE: {report.replay_safe ? 'YES' : 'NO'}
                </span>
                <span className={`chip ${report.bounds_respected ? 'chip-green' : 'chip-red'}`}>
                  BOUNDS: {report.bounds_respected ? 'OK' : 'VIOLATED'}
                </span>
              </div>

              {/* Issues */}
              {[...report.dag_errors, ...report.bounds_violations, ...report.policy_violations, ...report.risk_details].map((msg, i) => (
                <div key={i} style={{ border: '2px solid var(--red)', padding: '8px 12px', background: '#ffd8d055', fontFamily: 'var(--font-mono)', fontSize: 12, color: '#cc2200' }}>
                  {msg}
                </div>
              ))}

              {/* Execution plan */}
              {report.execution_plan?.length > 0 && (
                <div style={{ border: 'var(--bw)', background: 'var(--white)' }}>
                  <div className="win-title" style={{ fontSize: 10 }}>EXECUTION PLAN</div>
                  {report.execution_plan.map((step, i) => (
                    <div key={i} style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '7px 12px', borderBottom: '1px solid var(--paper-3)',
                      fontFamily: 'var(--font-mono)', fontSize: 12,
                    }}>
                      <span style={{ color: '#2a2a2a', width: 20, textAlign: 'right', flexShrink: 0 }}>{i + 1}.</span>
                      {step}
                    </div>
                  ))}
                </div>
              )}

              {/* Hash */}
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#2a2a2a', wordBreak: 'break-all' }}>
                REPORT HASH: {report.report_hash}
              </div>

              {/* Submit */}
              {canExecute && !ledgerId && (
                <Tooltip tip="Submit this composition for real execution.\nAgents will run and results will be recorded\nin the Ledger with a hash-chained audit trail.">
                  <button className="btn btn-green" onClick={submit} disabled={submitLoading}
                    style={{ display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'center', marginTop: 8, width: '100%' }}>
                    <Send size={13} /> {submitLoading ? 'SUBMITTING…' : 'APPROVE & SUBMIT'}
                  </button>
                </Tooltip>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
