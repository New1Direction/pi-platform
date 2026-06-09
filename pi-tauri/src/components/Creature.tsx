import { spriteGrid } from '../lib/agentdex';

// A deterministic pixel "creature" rendered from an agent's name. Placeholder
// for real type-art — swap by dropping sprites in src/assets and keying on type.
export function Creature({ seed, color, size = 48 }: { seed: string; color: string; size?: number }) {
  const grid = spriteGrid(seed);
  const N = 7;
  return (
    <svg
      width={size} height={size} viewBox={`0 0 ${N} ${N}`}
      shapeRendering="crispEdges"
      style={{ imageRendering: 'pixelated', display: 'block', filter: `drop-shadow(0 0 3px ${color}66)` }}
    >
      {grid.flatMap((row, r) =>
        row.map((on, c) => (on ? (
          <rect key={`${r}-${c}`} x={c} y={r} width={1} height={1} fill={color} />
        ) : null)),
      )}
      {/* eyes on top of the body */}
      <rect x={2} y={2} width={1} height={1} fill="#0c0c0c" />
      <rect x={4} y={2} width={1} height={1} fill="#0c0c0c" />
    </svg>
  );
}
