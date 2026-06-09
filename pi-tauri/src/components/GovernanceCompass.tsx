import { heading as computeHeading } from '../lib/governance';
import type { GovSignals } from '../lib/governance';

const ARROW: Record<number, string> = { 0: '↑', 90: '→', 135: '↘', 180: '↓', 225: '↙', 270: '←' };

// A governance "compass": shows which way an action (or the fleet) is pulling
// across the risk/trust/anomaly/… axes. North is the Safety *attractor* — a
// direction you orient toward, not a destination you arrive at. The absolute
// angle is decorative; the deflection from North is the signal. A lens, not a
// control: the gate still enforces underneath.
export function GovernanceCompass({ signals, title, caption }: { signals: GovSignals; title?: string; caption?: string }) {
  const h = computeHeading(signals);
  const C = 100;
  const R = 82;
  const pt = (angleDeg: number, r: number) => {
    const rad = (angleDeg * Math.PI) / 180;
    return { x: C + r * Math.sin(rad), y: C - r * Math.cos(rad) };
  };

  const needleLen = Math.max(0.18, h.magnitude) * R;
  const tip = pt(h.headingDeg, needleLen);
  const tail = pt((h.headingDeg + 180) % 360, needleLen * 0.34);
  const wRad = ((h.headingDeg + 90) % 360) * (Math.PI / 180);
  const w = 6;
  const cL = { x: C + w * Math.sin(wRad), y: C - w * Math.cos(wRad) };
  const cR = { x: C - w * Math.sin(wRad), y: C + w * Math.cos(wRad) };

  return (
    <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
      <svg width={160} height={160} viewBox="0 0 200 200" style={{ flexShrink: 0 }}>
        {/* safe zone wedge at north */}
        <path d={`M ${C} ${C} L ${pt(330, R).x} ${pt(330, R).y} A ${R} ${R} 0 0 1 ${pt(30, R).x} ${pt(30, R).y} Z`}
          fill="#2a9d4a" opacity={0.1} />
        {/* face */}
        <circle cx={C} cy={C} r={R} fill="var(--surface-2)" stroke="var(--paper-3)" strokeWidth={2} />
        {/* cardinal ticks */}
        {[0, 90, 180, 270].map(a => {
          const o = pt(a, R); const i = pt(a, R - 8);
          return <line key={a} x1={i.x} y1={i.y} x2={o.x} y2={o.y} stroke="var(--text-muted)" strokeWidth={1.5} />;
        })}
        {/* axis spokes */}
        {h.axes.map(ax => {
          const e = pt(ax.angleDeg, ax.force * R);
          return (
            <g key={ax.key}>
              <line x1={C} y1={C} x2={e.x} y2={e.y} stroke={ax.color} strokeWidth={2} opacity={0.5} />
              <circle cx={e.x} cy={e.y} r={3} fill={ax.color} />
            </g>
          );
        })}
        {/* needle */}
        <polygon points={`${tip.x},${tip.y} ${cL.x},${cL.y} ${tail.x},${tail.y} ${cR.x},${cR.y}`}
          fill={h.color} stroke={h.color} strokeWidth={1} strokeLinejoin="round" />
        <circle cx={C} cy={C} r={5} fill="var(--surface)" stroke="var(--text)" strokeWidth={1.5} />
        {/* N marker */}
        <text x={C} y={16} textAnchor="middle" style={{ fontFamily: 'var(--font-pixel)', fontSize: 7, fill: '#2a9d4a' }}>SAFE</text>
      </svg>

      <div style={{ flex: 1, minWidth: 180 }}>
        {title && (
          <div style={{ fontFamily: 'var(--font-ui)', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)', marginBottom: 2 }}>
            {title}
          </div>
        )}
        <div style={{ fontFamily: 'var(--font-ui)', fontSize: 16, fontWeight: 800, color: h.color, lineHeight: 1.1 }}>
          {h.label}
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>
          {h.deflection.toFixed(0)}° off Safe · {(h.alignment * 100).toFixed(0)}% aligned
        </div>

        {/* per-axis warmer/colder readout */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {h.axes.map(ax => (
            <div key={ax.key} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 14, textAlign: 'center', color: ax.color, fontWeight: 700 }}>{ARROW[ax.angleDeg] ?? '·'}</span>
              <span style={{ width: 78, fontFamily: 'var(--font-ui)', fontSize: 11, color: 'var(--text)' }}>{ax.label}</span>
              <div style={{ flex: 1, height: 5, background: 'var(--paper-3)', overflow: 'hidden' }}>
                <div style={{ width: `${ax.force * 100}%`, height: '100%', background: ax.color }} />
              </div>
            </div>
          ))}
        </div>

        {caption && (
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 8, lineHeight: 1.4 }}>
            {caption}
          </div>
        )}
      </div>
    </div>
  );
}
