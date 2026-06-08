import { useState, useEffect } from 'react';
import { Search } from 'lucide-react';
import { listAllCapabilities } from '../lib/api';
import { humanizeAgentName } from '../lib/humanize';
import type { MarketplaceCapability } from '../types';

const TRUST_CHIP: Record<string, string> = {
  GOVERNED:   'chip-ink',
  AUDITED:    'chip-blue',
  VERIFIED:   'chip-green',
  UNVERIFIED: 'chip-yellow',
};

function CapCard({ cap }: { cap: MarketplaceCapability }) {
  const title = humanizeAgentName(cap.agent_name || cap.capability_id.replace(/^cap_/, ''));
  const tags = cap.compatibility_tags ?? [];
  return (
    <div style={{
      border: 'var(--bw)', boxShadow: 'var(--shadow-sm)',
      background: 'var(--white)',
      display: 'flex', flexDirection: 'column',
    }}>
      {/* Header: trust tier + schema version */}
      <div style={{
        padding: '7px 11px',
        borderBottom: '1px solid var(--paper-3)',
        background: 'var(--paper-2)',
        display: 'flex', alignItems: 'center', gap: 8,
      }}>
        <span className={`chip ${TRUST_CHIP[cap.trust_tier] ?? 'chip-ink'}`}>{cap.trust_tier}</span>
        <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
          v{cap.schema_version}
        </span>
      </div>

      {/* Body: human-readable name + plain-English description */}
      <div style={{ padding: '10px 11px', flex: 1 }}>
        <div style={{
          fontFamily: 'var(--font-ui)', fontSize: 15, fontWeight: 700,
          color: 'var(--text)', marginBottom: 5, lineHeight: 1.2,
        }}>
          {title}
        </div>
        <div style={{ fontFamily: 'var(--font-ui)', fontSize: 13, color: 'var(--text)', lineHeight: 1.45 }}>
          {cap.description}
        </div>
      </div>

      {/* Footer: what it triggers on (readable pills, not tiny uppercase) */}
      {tags.length > 0 && (
        <div style={{ padding: '8px 11px', borderTop: '1px solid var(--paper-3)' }}>
          <div style={{
            fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 700,
            color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 5,
          }}>
            Triggers on
          </div>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {tags.slice(0, 4).map(t => (
              <span key={t} style={{
                fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text)',
                padding: '2px 7px', background: 'var(--paper-2)',
                border: '1px solid var(--paper-3)',
              }}>{t}</span>
            ))}
            {tags.length > 4 && (
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', padding: '2px 4px' }}>
                +{tags.length - 4} more
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export function RegistryView() {
  const [caps, setCaps] = useState<MarketplaceCapability[]>([]);
  const [filtered, setFiltered] = useState<MarketplaceCapability[]>([]);
  const [search, setSearch] = useState('');
  const [trust, setTrust] = useState<string>('ALL');
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const reload = () => {
    setLoading(true);
    setLoadError(null);
    listAllCapabilities()
      .then(r => { setCaps(r.capabilities); setFiltered(r.capabilities); })
      .catch(e => setLoadError(String(e)))
      .finally(() => setLoading(false));
  };

  useEffect(() => { reload(); }, []);

  useEffect(() => {
    const q = search.toLowerCase();
    setFiltered(caps.filter(c => {
      const matchSearch = !q ||
        humanizeAgentName(c.agent_name || '').toLowerCase().includes(q) ||
        c.agent_name?.toLowerCase().includes(q) ||
        c.description?.toLowerCase().includes(q) ||
        c.compatibility_tags?.some(t => t.toLowerCase().includes(q));
      const matchTrust = trust === 'ALL' || c.trust_tier === trust;
      return matchSearch && matchTrust;
    }));
  }, [search, trust, caps]);

  const tiers = ['ALL', 'GOVERNED', 'AUDITED', 'VERIFIED', 'UNVERIFIED'];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>

      {/* ── Toolbar ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '10px 16px', borderBottom: 'var(--bw)',
        background: 'var(--paper-2)', flexShrink: 0,
      }}>
        <div style={{ display: 'flex', flex: 1, alignItems: 'center', border: 'var(--bw)', background: 'var(--white)' }}>
          <Search size={13} style={{ margin: '0 8px', color: 'var(--text-muted)', flexShrink: 0 }} />
          <input className="input" style={{ border: 'none', boxShadow: 'none', flex: 1 }}
            placeholder="search agents, runtimes, tags…"
            value={search} onChange={e => setSearch(e.target.value)} />
        </div>

        {/* Trust filter */}
        <div style={{ display: 'flex', gap: 0, border: 'var(--bw)', flexShrink: 0 }}>
          {tiers.map((t, i) => (
            <button key={t} onClick={() => setTrust(t)} style={{
              padding: '5px 10px',
              background: trust === t ? 'var(--ink)' : 'var(--white)',
              color: trust === t ? 'var(--white)' : 'var(--ink)',
              border: 'none',
              borderRight: i < tiers.length - 1 ? '1px solid var(--paper-3)' : 'none',
              fontFamily: 'var(--font-mono)', fontSize: 10, fontWeight: 600,
              letterSpacing: '0.05em', textTransform: 'uppercase', cursor: 'pointer',
            }}>{t}</button>
          ))}
        </div>

        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
          {loading ? 'loading…' : loadError ? 'load failed' : `${filtered.length} / ${caps.length} agents`}
        </span>
        <button className="btn btn-sm" onClick={reload} disabled={loading} style={{ flexShrink: 0 }}>
          ↺ Reload
        </button>
      </div>

      {/* ── Grid ── */}
      <div style={{
        flex: 1, overflow: 'auto',
        padding: 16,
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
        gap: 12,
        alignContent: 'start',
      }}>
        {filtered.map(c => <CapCard key={c.capability_id} cap={c} />)}
        {!loading && loadError && (
          <div style={{ gridColumn: '1/-1', textAlign: 'center', padding: 48 }}>
            <div style={{ fontFamily: 'var(--font-ui)', fontSize: 14, fontWeight: 700, color: '#cc0022', marginBottom: 8 }}>Backend unreachable</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', marginBottom: 16 }}>{loadError}</div>
            <button className="btn" onClick={reload}>↺ Retry connection</button>
          </div>
        )}
        {!loading && !loadError && filtered.length === 0 && (
          <div style={{ gridColumn: '1/-1', textAlign: 'center', padding: 48 }}>
            <div style={{ fontFamily: 'var(--font-ui)', fontSize: 15, fontWeight: 700, marginBottom: 8 }}>No agents match</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)' }}>Try a broader search or different trust tier filter.</div>
          </div>
        )}
      </div>
    </div>
  );
}
