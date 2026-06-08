import { useState, useEffect } from 'react';
import { Search } from 'lucide-react';
import { listAllCapabilities } from '../lib/api';
import type { MarketplaceCapability } from '../types';

const TRUST_CHIP: Record<string, string> = {
  GOVERNED:   'chip-ink',
  AUDITED:    'chip-blue',
  VERIFIED:   'chip-green',
  UNVERIFIED: 'chip-yellow',
};

function CapCard({ cap }: { cap: MarketplaceCapability }) {
  return (
    <div style={{
      border: 'var(--bw)', boxShadow: 'var(--shadow-sm)',
      background: 'var(--white)',
      display: 'flex', flexDirection: 'column',
    }}>
      <div style={{
        padding: '7px 10px',
        borderBottom: 'var(--bw)',
        background: 'var(--paper-2)',
        display: 'flex', alignItems: 'center', gap: 6,
      }}>
        <span className={`chip ${TRUST_CHIP[cap.trust_tier] ?? 'chip-ink'}`}>{cap.trust_tier}</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: '#666' }}>{cap.runtime}</span>
        <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10, color: '#aaa' }}>v{cap.schema_version}</span>
      </div>
      <div style={{ padding: '8px 10px', flex: 1 }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 600, marginBottom: 4, wordBreak: 'break-all' }}>
          {cap.capability_id}
        </div>
        <div style={{ fontSize: 12, color: '#555', lineHeight: 1.4 }}>{cap.description}</div>
      </div>
      {cap.compatibility_tags?.length > 0 && (
        <div style={{ padding: '6px 10px', borderTop: '1px solid var(--paper-3)', display: 'flex', gap: 4, flexWrap: 'wrap' }}>
          {cap.compatibility_tags.slice(0, 4).map(t => (
            <span key={t} style={{
              fontFamily: 'var(--font-mono)', fontSize: 9,
              padding: '1px 5px', background: 'var(--paper-2)',
              border: '1px solid var(--paper-3)',
              textTransform: 'uppercase', letterSpacing: '0.04em',
            }}>{t}</span>
          ))}
          {cap.compatibility_tags.length > 4 && (
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#aaa' }}>+{cap.compatibility_tags.length - 4}</span>
          )}
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
        c.capability_id.toLowerCase().includes(q) ||
        c.description?.toLowerCase().includes(q) ||
        c.runtime?.toLowerCase().includes(q);
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
          <Search size={13} style={{ margin: '0 8px', color: '#888', flexShrink: 0 }} />
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

        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#888', whiteSpace: 'nowrap' }}>
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
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#888', marginBottom: 16 }}>{loadError}</div>
            <button className="btn" onClick={reload}>↺ Retry connection</button>
          </div>
        )}
        {!loading && !loadError && filtered.length === 0 && (
          <div style={{ gridColumn: '1/-1', textAlign: 'center', padding: 48 }}>
            <div style={{ fontFamily: 'var(--font-ui)', fontSize: 15, fontWeight: 700, marginBottom: 8 }}>No agents match</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#888' }}>Try a broader search or different trust tier filter.</div>
          </div>
        )}
      </div>
    </div>
  );
}
