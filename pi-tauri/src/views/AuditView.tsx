import { useState, useEffect } from 'react';
import { RefreshCw, ChevronDown, ChevronRight } from 'lucide-react';
import { getAuditLog } from '../lib/api';
import type { AuditLogEntry } from '../types';
import { format } from 'date-fns';

export function AuditView() {
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [actionFilter, setActionFilter] = useState('');

  const load = () => {
    setLoading(true);
    getAuditLog(200)
      .then(r => { setEntries(r.entries); setTotal(r.total); })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const filtered = actionFilter
    ? entries.filter(e => e.action?.toLowerCase().includes(actionFilter.toLowerCase()))
    : entries;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>

      {/* Toolbar */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '8px 16px', borderBottom: 'var(--bw)',
        background: 'var(--paper-2)', flexShrink: 0,
      }}>
        <input className="input" style={{ flex: 1, maxWidth: 320 }}
          placeholder="filter by action…"
          value={actionFilter} onChange={e => setActionFilter(e.target.value)} />
        <button className="btn btn-sm" onClick={load} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <RefreshCw size={12} /> REFRESH
        </button>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>
          {loading ? 'loading…' : `${filtered.length} / ${total} entries`}
        </span>
      </div>

      {/* Table */}
      <div style={{ flex: 1, overflow: 'auto' }}>
        <table className="brutal-table" style={{ tableLayout: 'fixed' }}>
          <colgroup>
            <col style={{ width: 26 }} />
            <col style={{ width: 155 }} />
            <col style={{ width: 160 }} />
            <col style={{ width: 130 }} />
            <col style={{ width: 100 }} />
            <col style={{ width: 120 }} />
          </colgroup>
          <thead>
            <tr>
              <th></th>
              <th>TIME</th>
              <th>ACTION</th>
              <th>REQUEST ID</th>
              <th>STATUS</th>
              <th>IP</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(e => (
              <>
                <tr
                  key={e.entry_id}
                  onClick={() => setExpanded(x => x === e.entry_id ? null : e.entry_id)}
                  style={{ cursor: 'pointer' }}
                  className={expanded === e.entry_id ? 'selected' : ''}
                >
                  <td style={{ textAlign: 'center', padding: '4px 4px' }}>
                    {expanded === e.entry_id ? <ChevronDown size={12} /> : <ChevronRight size={12} style={{ color: 'var(--text-muted)' }} />}
                  </td>
                  <td className="mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                    {e.timestamp ? format(new Date(e.timestamp), 'yyyy-MM-dd HH:mm:ss') : '—'}
                  </td>
                  <td style={{ fontWeight: 600, fontSize: 11 }}>{e.action}</td>
                  <td className="mono" style={{ fontSize: 10, color: 'var(--text-muted)' }}>{e.request_id?.slice(0, 18)}…</td>
                  <td>
                    <span className={`chip ${e.response_status === 'SUCCESS' || e.response_status?.startsWith('2') ? 'chip-green' : 'chip-red'}`}>
                      {e.response_status}
                    </span>
                  </td>
                  <td className="mono" style={{ fontSize: 10 }}>{e.user_ip}</td>
                </tr>
                {expanded === e.entry_id && (
                  <tr key={`${e.entry_id}-detail`}>
                    <td colSpan={6} style={{ padding: 0, borderBottom: 'var(--bw)' }}>
                      <pre style={{
                        margin: 0, padding: '12px 16px',
                        background: 'var(--ink)', color: 'var(--green)',
                        fontFamily: 'var(--font-mono)', fontSize: 11,
                        whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                        maxHeight: 200, overflow: 'auto',
                      }}>{JSON.stringify(e.structured_request, null, 2)}</pre>
                    </td>
                  </tr>
                )}
              </>
            ))}
            {!loading && filtered.length === 0 && (
              <tr><td colSpan={6} style={{ textAlign: 'center', padding: 32, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>no entries</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
