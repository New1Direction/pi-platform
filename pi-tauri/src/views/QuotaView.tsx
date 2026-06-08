import { useState, useEffect } from 'react';
import { RefreshCw, AlertTriangle } from 'lucide-react';
import { getTenantQuota } from '../lib/api';
import type { TenantQuotaStatus } from '../types';

function Bar({ label, value, max, accent }: { label: string; value: number; max: number; accent?: string }) {
  const pct = max > 0 ? Math.min((value / max) * 100, 100) : 0;
  const color = pct > 85 ? 'var(--red)' : pct > 65 ? 'var(--yellow)' : accent ?? 'var(--green)';

  return (
    <div style={{ border: 'var(--bw)', background: 'var(--white)', boxShadow: 'var(--shadow-sm)' }}>
      <div style={{
        background: 'var(--ink)', color: 'var(--white)',
        padding: '5px 12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        fontFamily: 'var(--font-sans)', fontSize: 11, fontWeight: 700,
        letterSpacing: '0.07em', textTransform: 'uppercase',
      }}>
        <span>{label}</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
          {value} / {max}
        </span>
      </div>
      <div style={{ padding: '12px 12px 14px' }}>
        <div style={{ height: 20, background: 'var(--paper-2)', border: '2px solid var(--ink)', position: 'relative' }}>
          <div style={{
            position: 'absolute', inset: 0, right: 'auto',
            width: `${pct}%`, background: color,
            transition: 'width 400ms',
          }} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
          <span>0</span>
          <span style={{ color, fontWeight: 700 }}>{pct.toFixed(0)}% used</span>
          <span>{max}</span>
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div style={{ border: 'var(--bw)', boxShadow: 'var(--shadow-sm)', background: 'var(--white)' }}>
      <div style={{
        background: 'var(--paper-2)', padding: '5px 12px', borderBottom: '1px solid var(--paper-3)',
        fontFamily: 'var(--font-sans)', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em',
      }}>{label}</div>
      <div style={{ padding: '10px 12px', fontFamily: 'var(--font-mono)', fontSize: 24, fontWeight: 700 }}>{value}</div>
    </div>
  );
}

export function QuotaView() {
  const [quota, setQuota] = useState<TenantQuotaStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [ts, setTs] = useState('');

  const load = () => {
    setLoading(true);
    getTenantQuota()
      .then(r => { setQuota(r.quota); setTs(new Date().toLocaleTimeString()); })
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: 24 }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
        <h2 style={{ fontFamily: 'var(--font-sans)', fontWeight: 700, fontSize: 18, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          Tenant Quota
        </h2>
        {quota?.quota_exceeded && (
          <span className="chip chip-red"><AlertTriangle size={10} style={{ marginRight: 4 }} /> QUOTA EXCEEDED</span>
        )}
        <button className="btn btn-sm" onClick={load} style={{ display: 'flex', alignItems: 'center', gap: 5, marginLeft: 'auto' }}>
          <RefreshCw size={12} /> REFRESH
        </button>
        {ts && <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>as of {ts}</span>}
      </div>

      {loading && <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)' }}>loading…</div>}

      {quota && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

          {/* Hourly bars */}
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10, color: 'var(--text-muted)' }}>
              — CURRENT HOUR —
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <Bar label="Compositions" value={quota.current_hour_compositions} max={quota.max_compositions_per_hour} />
              <Bar label="Simulations"  value={quota.current_hour_simulations}  max={quota.max_simulations_per_hour} />
            </div>
          </div>

          {/* Lifetime stats */}
          <div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10, color: 'var(--text-muted)' }}>
              — LIFETIME —
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 10 }}>
              <StatCard label="Submitted"  value={quota.compositions_submitted} />
              <StatCard label="Executed"   value={quota.compositions_executed} />
              <StatCard label="Simulated"  value={quota.simulations_run} />
              <StatCard label="Max nodes/composition" value={quota.max_nodes_per_composition} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
