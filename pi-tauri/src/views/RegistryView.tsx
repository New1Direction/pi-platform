import { useState, useEffect, useMemo } from 'react';
import { Search } from 'lucide-react';
import { listAllCapabilities } from '../lib/api';
import { humanizeAgentName } from '../lib/humanize';
import { agentTypeOf, agentStats, TYPES } from '../lib/agentdex';
import { Creature } from '../components/Creature';
import type { MarketplaceCapability } from '../types';

function StatBar({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <span className="forge-pixel" style={{ fontSize: 6, color: 'var(--text-muted)', width: 22, flexShrink: 0 }}>{label}</span>
      <div style={{ flex: 1, height: 6, background: 'var(--paper-3)', overflow: 'hidden' }}>
        <div style={{ width: `${value}%`, height: '100%', background: color }} />
      </div>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)', width: 16, textAlign: 'right' }}>{value}</span>
    </div>
  );
}

function DexCard({ cap, dexNo }: { cap: MarketplaceCapability; dexNo: number }) {
  const name = cap.agent_name || cap.capability_id.replace(/^cap_/, '');
  const title = humanizeAgentName(name);
  const tags = cap.compatibility_tags ?? [];
  const type = agentTypeOf(name, tags);
  const stats = agentStats(name, tags);

  return (
    <div style={{
      border: `2px solid ${type.color}`, background: 'var(--white)',
      display: 'flex', flexDirection: 'column', boxShadow: 'var(--shadow-sm)',
    }}>
      {/* type-colored header band */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 8px', background: type.color, color: '#fff' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 700, opacity: 0.9 }}>
          #{String(dexNo).padStart(3, '0')}
        </span>
        <span style={{ marginLeft: 'auto', fontFamily: 'var(--font-ui)', fontSize: 10, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 3 }}>
          {type.emoji} {type.label.toUpperCase()}
        </span>
        <span title="GOVERNED — live & signed off" style={{ fontSize: 11 }}>★</span>
      </div>

      {/* portrait + name */}
      <div style={{ display: 'flex', gap: 10, padding: '10px 10px 6px' }}>
        <div style={{
          width: 56, height: 56, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: 'var(--surface-2)', border: '1px solid var(--paper-3)',
        }}>
          <Creature seed={name} color={type.color} size={46} />
        </div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontFamily: 'var(--font-ui)', fontSize: 14, fontWeight: 700, color: 'var(--text)', lineHeight: 1.15, marginBottom: 4 }}>
            {title}
          </div>
          <div style={{ fontFamily: 'var(--font-ui)', fontSize: 11.5, color: 'var(--text)', lineHeight: 1.35, display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }}>
            {cap.description}
          </div>
        </div>
      </div>

      {/* stats */}
      <div style={{ padding: '2px 10px 8px', display: 'flex', flexDirection: 'column', gap: 4 }}>
        <StatBar label="POW" value={stats.POW} color={type.color} />
        <StatBar label="CVR" value={stats.CVR} color={type.color} />
        <StatBar label="SPD" value={stats.SPD} color={type.color} />
      </div>

      {/* moves */}
      {tags.length > 0 && (
        <div style={{ padding: '6px 10px', borderTop: '1px solid var(--paper-3)' }}>
          <div className="forge-pixel" style={{ fontSize: 6, color: 'var(--text-muted)', marginBottom: 5 }}>MOVES</div>
          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
            {tags.slice(0, 3).map(t => (
              <span key={t} style={{
                fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text)',
                padding: '2px 6px', background: 'var(--surface-2)', border: `1px solid ${type.color}55`,
              }}>{t}</span>
            ))}
            {tags.length > 3 && <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', padding: '2px 3px' }}>+{tags.length - 3}</span>}
          </div>
        </div>
      )}
    </div>
  );
}

export function RegistryView() {
  const [caps, setCaps] = useState<MarketplaceCapability[]>([]);
  const [search, setSearch] = useState('');
  const [typeKey, setTypeKey] = useState<string>('ALL');
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const reload = () => {
    setLoading(true);
    setLoadError(null);
    listAllCapabilities()
      .then(r => setCaps(r.capabilities))
      .catch(e => setLoadError(String(e)))
      .finally(() => setLoading(false));
  };
  useEffect(() => { reload(); }, []);

  // Stable dex number per agent (position in the full, name-sorted list).
  const dexNoById = useMemo(() => {
    const m = new Map<string, number>();
    caps.forEach((c, i) => m.set(c.capability_id, i + 1));
    return m;
  }, [caps]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return caps.filter(c => {
      const name = c.agent_name || '';
      const matchSearch = !q ||
        humanizeAgentName(name).toLowerCase().includes(q) ||
        name.toLowerCase().includes(q) ||
        c.description?.toLowerCase().includes(q) ||
        c.compatibility_tags?.some(t => t.toLowerCase().includes(q));
      const matchType = typeKey === 'ALL' || agentTypeOf(name, c.compatibility_tags ?? []).key === typeKey;
      return matchSearch && matchType;
    });
  }, [search, typeKey, caps]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', flex: 1, overflow: 'hidden' }}>

      {/* ── Dex header ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12,
        padding: '8px 16px', borderBottom: 'var(--bw)',
        background: 'linear-gradient(180deg, #2a1c12, #1c1510)', flexShrink: 0,
      }}>
        <span className="forge-pixel" style={{ fontSize: 11, color: 'var(--heat)' }}>AGENTDEX</span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: '#c9a784' }}>
          {loading ? 'loading…' : loadError ? 'offline' : `${caps.length} captured · gotta scan 'em all`}
        </span>
        <div style={{ display: 'flex', flex: 1, maxWidth: 320, alignItems: 'center', border: '1px solid var(--ember)', background: '#120d0a', marginLeft: 'auto' }}>
          <Search size={13} style={{ margin: '0 8px', color: 'var(--heat)', flexShrink: 0 }} />
          <input
            value={search} onChange={e => setSearch(e.target.value)}
            placeholder="search the dex…"
            style={{ flex: 1, border: 'none', outline: 'none', background: 'transparent', color: '#ffe9d6', fontFamily: 'var(--font-mono)', fontSize: 12, padding: '5px 8px 5px 0' }}
          />
        </div>
      </div>

      {/* ── Type filter ── */}
      <div style={{ display: 'flex', gap: 5, padding: '8px 16px', borderBottom: 'var(--bw)', background: 'var(--paper-2)', flexShrink: 0, overflowX: 'auto' }}>
        <button onClick={() => setTypeKey('ALL')} style={{
          padding: '3px 9px', flexShrink: 0, cursor: 'pointer',
          background: typeKey === 'ALL' ? 'var(--ink)' : 'var(--white)', color: typeKey === 'ALL' ? 'var(--white)' : 'var(--ink)',
          border: 'var(--bw)', fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 700,
        }}>ALL</button>
        {TYPES.map(t => {
          const on = typeKey === t.key;
          const n = caps.filter(c => agentTypeOf(c.agent_name || '', c.compatibility_tags ?? []).key === t.key).length;
          if (n === 0) return null;
          return (
            <button key={t.key} onClick={() => setTypeKey(t.key)} style={{
              padding: '3px 9px', flexShrink: 0, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4,
              background: on ? t.color : 'var(--white)', color: on ? '#fff' : 'var(--text)',
              border: `1px solid ${t.color}`, fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 700, whiteSpace: 'nowrap',
            }}>
              {t.emoji} {t.label} <span style={{ opacity: 0.7, fontWeight: 400 }}>{n}</span>
            </button>
          );
        })}
      </div>

      {/* ── Card grid ── */}
      <div style={{
        flex: 1, overflow: 'auto', padding: 16,
        display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 12, alignContent: 'start',
      }}>
        {filtered.map(c => <DexCard key={c.capability_id} cap={c} dexNo={dexNoById.get(c.capability_id) ?? 0} />)}

        {!loading && loadError && (
          <div style={{ gridColumn: '1/-1', textAlign: 'center', padding: 48 }}>
            <div style={{ fontFamily: 'var(--font-ui)', fontSize: 14, fontWeight: 700, color: '#cc0022', marginBottom: 8 }}>Dex offline — backend unreachable</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', marginBottom: 16 }}>{loadError}</div>
            <button className="btn" onClick={reload}>↺ Retry connection</button>
          </div>
        )}
        {!loading && !loadError && filtered.length === 0 && (
          <div style={{ gridColumn: '1/-1', textAlign: 'center', padding: 48 }}>
            <div style={{ fontFamily: 'var(--font-ui)', fontSize: 15, fontWeight: 700, marginBottom: 8, color: 'var(--text)' }}>No agents match</div>
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)' }}>Try a broader search or a different type.</div>
          </div>
        )}
      </div>
    </div>
  );
}
