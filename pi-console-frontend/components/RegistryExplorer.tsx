"use client";

import { MarketplaceCapability } from "@/types";

interface RegistryExplorerProps {
  capabilities: MarketplaceCapability[];
}

const trustColor: Record<string, string> = {
  UNVERIFIED: "#8b949e",
  VERIFIED: "#1f6feb",
  AUDITED: "#a371f7",
  GOVERNED: "#238636",
};

export default function RegistryExplorer({ capabilities }: RegistryExplorerProps) {
  return (
    <div className="flex flex-col gap-4 p-4 bg-[var(--card)] rounded-lg border border-[var(--border)] h-full overflow-auto">
      <h2 className="text-lg font-bold text-[var(--foreground)]">Registry Explorer</h2>
      <p className="text-xs text-[var(--muted-foreground)]">
        Browse capabilities from the Capability Marketplace Registry. Tenant-scoped.
      </p>
      <div className="flex flex-col gap-2">
        {capabilities.map((cap) => (
          <div key={cap.capability_id} className="border border-[var(--border)] rounded p-3 bg-[var(--background)]">
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm font-mono text-[var(--foreground)]">{cap.capability_id}</span>
              <span
                className="px-2 py-0.5 rounded text-xs font-bold text-white"
                style={{ backgroundColor: trustColor[cap.trust_tier] || "#30363d" }}
              >
                {cap.trust_tier}
              </span>
            </div>
            <div className="text-xs text-[var(--muted-foreground)]">
              {cap.runtime} :: {cap.operation}
            </div>
            <div className="text-sm text-[var(--foreground)] mt-1">{cap.description}</div>
            <div className="text-xs text-[var(--muted-foreground)] mt-1">
              Schema: {cap.schema_version} | Bounds: {JSON.stringify(cap.deterministic_bounds)}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
