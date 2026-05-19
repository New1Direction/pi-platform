"use client";

import { AuditLogEntry } from "@/types";

interface AuditLogViewerProps {
  entries: AuditLogEntry[];
  total: number;
}

export default function AuditLogViewer({ entries, total }: AuditLogViewerProps) {
  return (
    <div className="flex flex-col gap-4 p-4 bg-[var(--card)] rounded-lg border border-[var(--border)] h-full overflow-auto">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-bold text-[var(--foreground)]">Audit Log</h2>
        <span className="text-xs text-[var(--muted-foreground)]">Total: {total}</span>
      </div>
      <div className="flex flex-col gap-2">
        {entries.map((entry) => (
          <div key={entry.entry_id} className="border border-[var(--border)] rounded p-3 bg-[var(--background)]">
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-mono text-[var(--accent)]">{entry.entry_id}</span>
              <span className="text-xs text-[var(--muted-foreground)]">{entry.timestamp}</span>
            </div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2 py-0.5 rounded bg-[var(--secondary)] text-[var(--secondary-foreground)] text-xs font-bold">
                {entry.action}
              </span>
              <span className="text-xs text-[var(--muted-foreground)]">{entry.request_id}</span>
            </div>
            <div className="text-xs text-[var(--muted-foreground)]">IP: {entry.user_ip || "—"}</div>
            <pre className="text-xs bg-[var(--secondary)] rounded p-2 mt-2 overflow-auto max-h-[120px]">
              {JSON.stringify(entry.structured_request, null, 2)}
            </pre>
          </div>
        ))}
      </div>
    </div>
  );
}
