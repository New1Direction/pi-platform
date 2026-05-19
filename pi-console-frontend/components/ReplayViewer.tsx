"use client";

import { ExecutionReplayEvent } from "@/types";

interface ReplayViewerProps {
  events: ExecutionReplayEvent[];
  integrityVerified: boolean;
  totalEvents: number;
}

export default function ReplayViewer({ events, integrityVerified, totalEvents }: ReplayViewerProps) {
  return (
    <div className="flex flex-col gap-4 p-4 bg-[var(--card)] rounded-lg border border-[var(--border)] h-full overflow-auto">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-bold text-[var(--foreground)]">Execution Replay</h2>
        <div className="flex items-center gap-2">
          <span className="text-xs text-[var(--muted-foreground)]">Events: {totalEvents}</span>
          <span className={`px-2 py-0.5 rounded text-xs ${integrityVerified ? "bg-green-900 text-green-200" : "bg-red-900 text-red-200"}`}>
            {integrityVerified ? "Integrity Verified" : "Integrity Failed"}
          </span>
        </div>
      </div>
      <div className="flex flex-col gap-2">
        {events.map((ev) => (
          <div key={ev.sequence_number} className="border border-[var(--border)] rounded p-3 bg-[var(--background)]">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-mono text-[var(--accent)]">#{ev.sequence_number}</span>
              <span className="text-xs text-[var(--muted-foreground)]">{ev.emitted_by}</span>
            </div>
            <div className="text-sm text-[var(--foreground)] font-semibold">{ev.event_type}</div>
            <div className="text-xs text-[var(--muted-foreground)] mt-1">
              hash: {ev.event_hash.slice(0, 16)}... | prev: {ev.previous_hash.slice(0, 16) || "genesis"}...
            </div>
            {Object.keys(ev.payload_summary).length > 0 && (
              <pre className="text-xs bg-[var(--secondary)] rounded p-2 mt-2 overflow-auto">
                {JSON.stringify(ev.payload_summary, null, 2)}
              </pre>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
