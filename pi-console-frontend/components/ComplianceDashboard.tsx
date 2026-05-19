"use client";

import { TenantQuotaStatus } from "@/types";

interface ComplianceDashboardProps {
  quota: TenantQuotaStatus | null;
}

export default function ComplianceDashboard({ quota }: ComplianceDashboardProps) {
  return (
    <div className="flex flex-col gap-4 p-4 bg-[var(--card)] rounded-lg border border-[var(--border)] h-full overflow-auto">
      <h2 className="text-lg font-bold text-[var(--foreground)]">Compliance & Risk Dashboard</h2>
      <p className="text-xs text-[var(--muted-foreground)]">
        Tenant-scoped quota, blast radius metrics, and governance status.
      </p>
      {quota && (
        <div className="flex flex-col gap-3">
          <div className="grid grid-cols-2 gap-3">
            <MetricCard label="Compositions Submitted" value={quota.compositions_submitted} />
            <MetricCard label="Compositions Executed" value={quota.compositions_executed} />
            <MetricCard label="Simulations Run" value={quota.simulations_run} />
            <MetricCard label="Max Nodes / Composition" value={quota.max_nodes_per_composition} />
          </div>

          <div className="border border-[var(--border)] rounded p-3 mt-2">
            <p className="text-sm font-semibold text-[var(--foreground)] mb-2">Hourly Quota</p>
            <div className="flex flex-col gap-1">
              <QuotaBar label="Compositions" current={quota.current_hour_compositions} max={quota.max_compositions_per_hour} />
              <QuotaBar label="Simulations" current={quota.current_hour_simulations} max={quota.max_simulations_per_hour} />
            </div>
          </div>

          <div className={`border rounded p-3 mt-2 ${quota.quota_exceeded ? "border-red-900 bg-red-950/30" : "border-green-900 bg-green-950/30"}`}>
            <p className={`text-sm font-bold ${quota.quota_exceeded ? "text-red-300" : "text-green-300"}`}>
              {quota.quota_exceeded ? "QUOTA EXCEEDED" : "QUOTA NORMAL"}
            </p>
          </div>
        </div>
      )}
      {!quota && (
        <p className="text-[var(--muted-foreground)] text-sm">No quota data available.</p>
      )}
    </div>
  );
}

function MetricCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="border border-[var(--border)] rounded p-3 bg-[var(--background)]">
      <p className="text-xs text-[var(--muted-foreground)]">{label}</p>
      <p className="text-xl font-bold text-[var(--foreground)]">{value}</p>
    </div>
  );
}

function QuotaBar({ label, current, max }: { label: string; current: number; max: number }) {
  const pct = Math.min((current / max) * 100, 100);
  const color = pct > 90 ? "bg-red-600" : pct > 70 ? "bg-yellow-600" : "bg-green-600";
  return (
    <div className="flex flex-col gap-1">
      <div className="flex justify-between text-xs text-[var(--muted-foreground)]">
        <span>{label}</span>
        <span>{current} / {max}</span>
      </div>
      <div className="w-full bg-[var(--secondary)] rounded h-2">
        <div className={`${color} h-2 rounded`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}
