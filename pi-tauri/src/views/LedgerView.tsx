import { useState, useEffect, useCallback } from 'react';
import { RefreshCw, Search, AlertTriangle, CheckCircle2, XCircle, ChevronDown, ChevronRight } from 'lucide-react';
import { Tooltip } from '../components/Tooltip';
import { getLedgerTraces, getLedgerSummary, getLedgerTraceDetail } from '../lib/api';
import { agentTypeOf } from '../lib/agentdex';
import { humanizeAgentName } from '../lib/humanize';
import { Creature } from '../components/Creature';
import type { TraceListItem, LedgerSummaryResponse, TraceDetailResponse } from '../types';
import { format } from 'date-fns';

function riskChip(score?: number) {
  if (score == null) return null;
  if (score >= 80) return <span className="chip chip-red">{score.toFixed(0)}</span>;
  if (score >= 50) return <span className="chip chip-yellow">{score.toFixed(0)}</span>;
  return <span className="chip chip-green">{score.toFixed(0)}</span>;
}

function KpiCard({ label, value, accent }: { label: string; value: string | number; accent?: string }) {
  return (
    <div className="kpi-card">
      <div className="kpi-label" style={{ background: accent ?? 'var(--ink)' }}>{label}</div>
      <div className="kpi-value">{value}</div>
    </div>
  );
}

function TraceDetail({ traceId }: { traceId: string }) {
  const [detail, setDetail] = useState<TraceDetailResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    getLedgerTraceDetail(traceId)
      .then(setDetail)
      .catch(() => setDetail(null))
      .finally(() => setLoading(false));
  }, [traceId]);

  if (loading) return <div style={{ padding: 16, fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)' }}>loading…</div>;
  if (!detail) return <div style={{ padding: 16, fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--red)' }}>failed to load trace</div>;

  return (
    <div style={{ overflow: 'auto', height: '100%' }}>
      {/* Header row */}
      <div style={{ padding: '12px 16px', borderBottom: 'var(--bw)', background: 'var(--paper-2)' }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>TRACE ID</div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, wordBreak: 'break-all' }}>{detail.trace_id}</div>
      </div>

      {/* Fields */}
      {[
        ['Node', detail.node_name],
        ['Timestamp', detail.timestamp ? format(new Date(detail.timestamp), 'yyyy-MM-dd HH:mm:ss') : '—'],
        ['LLM Seed', String(detail.llm_seed)],
        ['LLM Temp', String(detail.llm_temperature)],
        ['Type Valid', detail.is_valid_type ? '✓ YES' : '✗ NO'],
        ...(detail.error_message ? [['Error', detail.error_message]] : []),
      ].map(([k, v]) => (
        <div key={k} style={{ display: 'flex', borderBottom: '1px solid var(--paper-3)' }}>
          <div style={{ width: 100, padding: '7px 12px', background: 'var(--paper-2)', fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', flexShrink: 0 }}>{k}</div>
          <div style={{ padding: '7px 12px', fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>{v}</div>
        </div>
      ))}

      {/* Raw output */}
      <div style={{ padding: 12 }}>
        <div style={{ fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>RAW OUTPUT</div>
        <pre style={{
          background: 'var(--ink)', color: 'var(--green)',
          padding: 12, fontFamily: 'var(--font-mono)', fontSize: 11,
          whiteSpace: 'pre-wrap', wordBreak: 'break-all',
          border: 'var(--bw)',
          maxHeight: 300, overflow: 'auto',
        }}>{detail.raw_output || '(empty)'}</pre>
      </div>
    </div>
  );
}

export function LedgerView() {
  const [traces, setTraces] = useState<TraceListItem[]>([]);
  const [summary, setSummary] = useState<LedgerSummaryResponse | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      getLedgerTraces(100, 0, { search: search || undefined }),
      getLedgerSummary(),
    ]).then(([t, s]) => {
      setTraces(t.traces);
      setTotal(t.total_count);
      setSummary(s);
    }).catch(console.error)
      .finally(() => setLoading(false));
  }, [search]);

  useEffect(() => { load(); }, [load]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>

      {/* ── KPI Row ── */}
      {summary && (
        <div style={{ display: 'flex', padding: '12px 16px', borderBottom: 'var(--bw)', flexShrink: 0, gap: 12 }}>
          <Tooltip tip="Total number of agent execution traces recorded in the ledger." wrapStyle={{ flex: 1 }}>
            <KpiCard label="Total Traces" value={summary.total_traces} />
          </Tooltip>
          <Tooltip tip="Percentage of executions that completed without error.\nGreen = healthy (>80%), Red = degraded." wrapStyle={{ flex: 1 }}>
            <KpiCard label="Success Rate" value={`${summary.success_rate.toFixed(1)}%`} accent="#005c22" />
          </Tooltip>
          <Tooltip tip="Average risk score across all traces (0–100).\n>50 = elevated risk, >80 = critical." wrapStyle={{ flex: 1 }}>
            <KpiCard label="Avg Risk Score" value={summary.avg_risk_score.toFixed(1)} accent={summary.avg_risk_score > 50 ? '#cc2200' : '#005c22'} />
          </Tooltip>
          <Tooltip tip="Executions flagged with anomalous behavior.\nClick a trace row to see anomaly details." wrapStyle={{ flex: 1 }}>
            <KpiCard label="Anomalies" value={summary.anomalies_count} accent={summary.anomalies_count > 0 ? '#cc2200' : undefined} />
          </Tooltip>
          <Tooltip tip="Traces where agent consensus diverged from the expected output.\nIndicates potential model instability." wrapStyle={{ flex: 1 }}>
            <KpiCard label="Consensus Alerts" value={summary.consensus_divergence_alerts} accent={summary.consensus_divergence_alerts > 0 ? '#7a6000' : undefined} />
          </Tooltip>
        </div>
      )}

      {/* ── Toolbar ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '8px 16px', borderBottom: 'var(--bw)',
        background: 'var(--paper-2)', flexShrink: 0,
      }}>
        <div style={{ display: 'flex', flex: 1, alignItems: 'center', border: 'var(--bw)', background: 'var(--white)', boxShadow: 'inset 1px 1px 0 var(--paper-3)' }}>
          <Search size={13} style={{ margin: '0 8px', color: 'var(--text-muted)', flexShrink: 0 }} />
          <input
            className="input" style={{ border: 'none', boxShadow: 'none', flex: 1 }}
            placeholder="search traces, agents, hashes…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && load()}
          />
        </div>
        <button className="btn btn-sm" onClick={load} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <RefreshCw size={12} className={loading ? 'spin' : ''} /> REFRESH
        </button>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
          {loading ? 'loading…' : `${total.toLocaleString()} traces`}
        </span>
      </div>

      {/* ── Split: table + detail ── */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>

        {/* Table */}
        <div style={{ flex: selected ? '0 0 60%' : 1, overflow: 'auto', borderRight: selected ? 'var(--bw)' : 'none' }}>
          <table className="brutal-table" style={{ tableLayout: 'fixed' }}>
            <colgroup>
              <col style={{ width: 26 }} />
              <col style={{ width: 100 }} />
              <col style={{ width: 160 }} />
              <col style={{ width: 80 }} />
              <col style={{ width: 70 }} />
              <col style={{ width: 160 }} />
              <col style={{ width: 140 }} />
            </colgroup>
            <thead>
              <tr>
                <th></th>
                <th><Tooltip tip="Pass/fail result of the execution.\n⚠ = anomaly detected." pos="bottom">STATUS</Tooltip></th>
                <th><Tooltip tip="Unique hash-chained trace identifier.\nClick to expand full trace details." pos="bottom">TRACE ID</Tooltip></th>
                <th><Tooltip tip="The specific micro-agent that handled this request,\nrouted by keyword dispatch." pos="bottom">AGENT</Tooltip></th>
                <th><Tooltip tip="Risk score 0–100.\nGreen <50 · Yellow 50–80 · Red >80." pos="bottom">RISK</Tooltip></th>
                <th><Tooltip tip="Composition node name that triggered\nthis execution." pos="bottom">NODE</Tooltip></th>
                <th><Tooltip tip="Execution timestamp (local time)." pos="bottom">TIME</Tooltip></th>
              </tr>
            </thead>
            <tbody>
              {traces.map(t => (
                <tr
                  key={t.id}
                  className={selected === t.trace_id ? 'selected' : ''}
                  onClick={() => setSelected(s => s === t.trace_id ? null : t.trace_id)}
                  style={{ cursor: 'pointer' }}
                >
                  <td style={{ textAlign: 'center', padding: '4px 4px' }}>
                    {selected === t.trace_id
                      ? <ChevronDown size={12} />
                      : <ChevronRight size={12} style={{ color: 'var(--text-muted)' }} />}
                  </td>
                  <td>
                    {t.success === false
                      ? <span className="chip chip-red"><XCircle size={9} style={{ marginRight: 3 }} />FAIL</span>
                      : t.success === true
                        ? <span className="chip chip-green"><CheckCircle2 size={9} style={{ marginRight: 3 }} />OK</span>
                        : <span className="chip chip-ink">—</span>}
                    {(t.anomalies_detected?.length ?? 0) > 0 && <AlertTriangle size={11} style={{ color: 'var(--yellow)', marginLeft: 4 }} />}
                  </td>
                  <td className="mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>{t.trace_id?.slice(0, 14)}…</td>
                  <td style={{ fontSize: 11 }}>
                    {t.routed_agent ? (
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                        <Creature seed={t.routed_agent} color={agentTypeOf(t.routed_agent, []).color} size={18} />
                        {humanizeAgentName(t.routed_agent)}
                      </span>
                    ) : '—'}
                  </td>
                  <td>{riskChip(t.risk_score)}</td>
                  <td style={{ fontSize: 11 }}>{t.node_name}</td>
                  <td className="mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                    {t.timestamp ? format(new Date(t.timestamp), 'MM-dd HH:mm:ss') : '—'}
                  </td>
                </tr>
              ))}
              {!loading && traces.length === 0 && (
                <tr><td colSpan={7} style={{ padding: 0 }}>
                  <div style={{
                    margin: 24, padding: '24px 32px',
                    border: '2px solid var(--chrome-dd)',
                    boxShadow: 'inset 1px 1px 0 #808080',
                    background: 'var(--surface-2)',
                    textAlign: 'center',
                  }}>
                    <div style={{
                      fontFamily: 'var(--font-ui)', fontSize: 14, fontWeight: 700,
                      color: 'var(--text)', marginBottom: 10, letterSpacing: '0.01em',
                    }}>
                      No battles yet
                    </div>
                    <div style={{
                      fontFamily: 'var(--font-ui)', fontSize: 12, color: 'var(--text)',
                      lineHeight: 1.8, maxWidth: 420, margin: '0 auto',
                    }}>
                      Head to the <strong>Party</strong> tab, pick a team, drop in a file, and <strong>Run</strong>.<br />
                      Every scan your agents run shows up here as a hash-chained trace.
                    </div>
                  </div>
                </td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Detail pane */}
        {selected && (
          <div style={{ flex: '0 0 40%', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
            <div className="win-title">
              
              TRACE DETAIL
              <button className="btn btn-sm" style={{ marginLeft: 'auto', color: 'var(--ink)', background: 'var(--white)' }} onClick={() => setSelected(null)}>CLOSE ×</button>
            </div>
            <div style={{ flex: 1, overflow: 'auto' }}>
              <TraceDetail traceId={selected} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
