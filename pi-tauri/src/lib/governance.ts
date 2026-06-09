// Governance as navigation — compose the signals the orchestrator already emits
// into a heading. Axes are forces on a compass: a "Safe" attractor at North,
// repulsors (risk, anomaly, instability, …) deflecting the needle.
//
// IMPORTANT: this is a LENS. It reads existing signals and shows a direction.
// It changes what you SEE, never what the system ENFORCES (the gate/walls are
// unchanged and authoritative). Pure + deterministic — same signals, same heading.

const clamp01 = (n: number): number => (n < 0 ? 0 : n > 1 ? 1 : n);

export interface GovSignals {
  risk: number; // 0..100 — the dominant axis
  trust?: number; // 0..1 attractor strength (GOVERNED≈1 … UNVERIFIED≈0.25); default 1
  anomaly?: number; // 0..1 repel
  unstable?: number; // 0..1 repel (consensus divergence / failure)
  cost?: number; // 0..1 repel (slots in when the backend exposes it)
  latency?: number; // 0..1 repel (ditto)
}

export interface CompassAxis {
  key: string;
  label: string;
  angleDeg: number; // 0=N, 90=E, 180=S, 270=W
  force: number; // 0..1
  kind: 'attract' | 'repel';
  color: string;
}

export interface Heading {
  axes: CompassAxis[];
  headingDeg: number; // resultant direction (0=N, clockwise)
  magnitude: number; // 0..1 — how coherent/strong the pull is
  alignment: number; // 0..1 — 1 = pointing straight to Safe (North)
  deflection: number; // 0..180 degrees off North
  label: string;
  color: string;
}

const ALIGN_GREEN = '#2a9d4a';
const ALIGN_AMBER = '#c9a200';
const ALIGN_RED = '#cc2200';

export function trustScore(tier: string | undefined): number {
  switch ((tier ?? '').toUpperCase()) {
    case 'GOVERNED':
      return 1;
    case 'AUDITED':
      return 0.75;
    case 'VERIFIED':
      return 0.5;
    case 'UNVERIFIED':
      return 0.25;
    default:
      return 0.85;
  }
}

export function heading(signals: GovSignals): Heading {
  const risk = clamp01(signals.risk / 100);
  const trust = clamp01(signals.trust ?? 1);
  const anomaly = clamp01(signals.anomaly ?? 0);
  const unstable = clamp01(signals.unstable ?? 0);
  const cost = clamp01(signals.cost ?? 0);
  const latency = clamp01(signals.latency ?? 0);

  // Safe attractor strength: trustworthy AND low-risk pulls hardest toward North.
  const safe = clamp01(trust * (1 - risk));

  const candidates: CompassAxis[] = [
    { key: 'safe', label: 'Safe', angleDeg: 0, force: safe, kind: 'attract', color: ALIGN_GREEN },
    { key: 'risk', label: 'Risk', angleDeg: 180, force: risk, kind: 'repel', color: ALIGN_RED },
    { key: 'anomaly', label: 'Anomaly', angleDeg: 90, force: anomaly, kind: 'repel', color: '#e07000' },
    { key: 'unstable', label: 'Instability', angleDeg: 270, force: unstable, kind: 'repel', color: ALIGN_AMBER },
    { key: 'cost', label: 'Cost', angleDeg: 135, force: cost, kind: 'repel', color: '#7a4fff' },
    { key: 'latency', label: 'Latency', angleDeg: 225, force: latency, kind: 'repel', color: '#3aa0ff' },
  ];
  // Always keep the two core axes; include the rest only when they actually pull.
  const axes = candidates.filter(a => a.key === 'safe' || a.key === 'risk' || a.force > 0.001);

  let x = 0;
  let y = 0;
  let total = 0;
  for (const a of axes) {
    const rad = (a.angleDeg * Math.PI) / 180;
    x += a.force * Math.sin(rad); // East
    y += a.force * Math.cos(rad); // North
    total += a.force;
  }

  const headingDeg = (((Math.atan2(x, y) * 180) / Math.PI) + 360) % 360;
  const magnitude = total > 0 ? clamp01(Math.hypot(x, y) / total) : 0;
  const deflection = Math.min(headingDeg, 360 - headingDeg); // 0..180 off North
  const alignment = clamp01(1 - deflection / 180);

  const label =
    deflection < 25 ? 'Clear heading — safe' : deflection < 70 ? 'Drifting — adjust course' : 'Off course';
  const color = alignment > 0.7 ? ALIGN_GREEN : alignment > 0.45 ? ALIGN_AMBER : ALIGN_RED;

  return { axes, headingDeg, magnitude, alignment, deflection, label, color };
}
