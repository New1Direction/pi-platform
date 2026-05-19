"use client";

import { SimulationReport } from "@/types";

interface SimulationPanelProps {
  report: SimulationReport | null;
  onRun?: () => void;
  onApprove?: () => void;
  loading?: boolean;
}

export default function SimulationPanel({ report, onRun, onApprove, loading }: SimulationPanelProps) {
  return (
    <div className="flex flex-col gap-4 p-4 bg-[var(--card)] rounded-lg border border-[var(--border)] h-full overflow-auto">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-bold text-[var(--foreground)]">Simulation Preview</h2>
        <button
          onClick={onRun}
          disabled={loading}
          className="bg-[var(--accent)] text-[var(--accent-foreground)] px-4 py-1 rounded text-sm hover:opacity-90 disabled:opacity-50"
        >
          {loading ? "Simulating..." : "Run Simulation"}
        </button>
      </div>
      {!report && (
        <p className="text-[var(--muted-foreground)] text-sm">
          Build a DAG and click Run Simulation to preview execution plan, bounds checks, and risk assessment.
        </p>
      )}
      {report && (
        <div className="flex flex-col gap-3 text-sm">
          <div className="flex gap-2">
            <span className="px-2 py-0.5 rounded bg-[var(--secondary)] text-[var(--secondary-foreground)]">{report.report_id}</span>
            <RiskBadge level={report.risk_level} />
            <span className={`px-2 py-0.5 rounded ${report.replay_safe ? "bg-green-900 text-green-200" : "bg-red-900 text-red-200"}`}>
              {report.replay_safe ? "Replay Safe" : "Replay Unsafe"}
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <StatusRow label="DAG Valid" value={report.dag_valid ? "Yes" : "No"} ok={report.dag_valid} />
            <StatusRow label="Bounds Respected" value={report.bounds_respected ? "Yes" : "No"} ok={report.bounds_respected} />
          </div>

          {report.dag_errors.length > 0 && (
            <div className="bg-red-950/40 border border-red-900 rounded p-2">
              <p className="font-semibold text-red-300">DAG Errors</p>
              <ul className="list-disc list-inside text-red-200">
                {report.dag_errors.map((e, i) => <li key={i}>{e}</li>)}
              </ul>
            </div>
          )}

          {report.bounds_violations.length > 0 && (
            <div className="bg-red-950/40 border border-red-900 rounded p-2">
              <p className="font-semibold text-red-300">Bounds Violations</p>
              <ul className="list-disc list-inside text-red-200">
                {report.bounds_violations.map((e, i) => <li key={i}>{e}</li>)}
              </ul>
            </div>
          )}

          {report.risk_details.length > 0 && (
            <div className="bg-yellow-950/40 border border-yellow-900 rounded p-2">
              <p className="font-semibold text-yellow-300">Risk Details</p>
              <ul className="list-disc list-inside text-yellow-200">
                {report.risk_details.map((e, i) => <li key={i}>{e}</li>)}
              </ul>
            </div>
          )}

          <div>
            <p className="font-semibold text-[var(--foreground)]">Execution Plan</p>
            <ol className="list-decimal list-inside text-[var(--muted-foreground)]">
              {report.execution_plan.map((step, i) => <li key={i}>{step}</li>)}
            </ol>
          </div>

          {report.can_execute && (
            <button
              onClick={onApprove}
              disabled={loading}
              className="bg-[var(--primary)] text-[var(--primary-foreground)] px-4 py-2 rounded font-semibold hover:opacity-90 disabled:opacity-50 mt-2"
            >
              {loading ? "Submitting..." : "Approve & Submit to Core"}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function RiskBadge({ level }: { level: string }) {
  const colors: Record<string, string> = {
    NONE: "bg-green-900 text-green-200",
    LOW: "bg-emerald-900 text-emerald-200",
    MEDIUM: "bg-yellow-900 text-yellow-200",
    HIGH: "bg-orange-900 text-orange-200",
    CRITICAL: "bg-red-900 text-red-200",
  };
  return <span className={`px-2 py-0.5 rounded text-xs font-bold ${colors[level] || colors.NONE}`}>{level}</span>;
}

function StatusRow({ label, value, ok }: { label: string; value: string; ok: boolean }) {
  return (
    <div className={`flex justify-between px-2 py-1 rounded border ${ok ? "border-green-900 bg-green-950/30" : "border-red-900 bg-red-950/30"}`}>
      <span className="text-[var(--muted-foreground)]">{label}</span>
      <span className={ok ? "text-green-300" : "text-red-300"}>{value}</span>
    </div>
  );
}
