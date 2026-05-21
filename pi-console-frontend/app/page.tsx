"use client";

import { useEffect } from "react";
import { useConsole } from "@/hooks/useConsole";
import DagVisualizer from "@/components/DagVisualizer";
import SimulationPanel from "@/components/SimulationPanel";
import ChatPanel from "@/components/ChatPanel";
import ReplayViewer from "@/components/ReplayViewer";
import AuditLogViewer from "@/components/AuditLogViewer";
import RegistryExplorer from "@/components/RegistryExplorer";
import ComplianceDashboard from "@/components/ComplianceDashboard";

const TAB_BUTTONS: { mode: ReturnType<typeof useConsole>["state"]["mode"]; label: string }[] = [
  { mode: "builder", label: "Visual Builder" },
  { mode: "chat", label: "Chat / Agent" },
  { mode: "replay", label: "Replay" },
  { mode: "audit", label: "Audit Log" },
  { mode: "registry", label: "Registry" },
  { mode: "compliance", label: "Compliance" },
];

export default function ConsolePage() {
  const {
    state,
    setMode,
    initSession,
    buildComposition,
    runSimulation,
    approveAndSubmit,
    sendChat,
    loadCapabilities,
    loadAuditLog,
    loadQuota,
  } = useConsole("default");

  useEffect(() => {
    initSession();
    loadCapabilities();
    loadQuota();
  }, [initSession, loadCapabilities, loadQuota]);

  useEffect(() => {
    if (state.mode === "audit") loadAuditLog();
    if (state.mode === "compliance") loadQuota();
  }, [state.mode, loadAuditLog, loadQuota]);

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="border-b border-[var(--border)] bg-[var(--card)] px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-3 h-3 rounded-full bg-[var(--primary)]" />
          <h1 className="text-lg font-bold tracking-tight text-[var(--foreground)]">PI CONSOLE</h1>
          <span className="text-xs text-[var(--muted-foreground)] border border-[var(--border)] rounded px-2 py-0.5">
            Layer 4 — Human Interface
          </span>
        </div>
        <div className="flex items-center gap-3 text-xs">
          <span className="text-[var(--muted-foreground)]">Tenant: <span className="text-[var(--foreground)]">{state.tenantId}</span></span>
          <span className="text-[var(--muted-foreground)]">Session: <span className="font-mono text-[var(--foreground)]">{state.sessionId.slice(0, 12)}...</span></span>
          <span className={`px-2 py-0.5 rounded text-xs ${state.llmEnabled ? "bg-[var(--accent)] text-white" : "bg-[var(--secondary)] text-[var(--muted-foreground)]"}`}>
            LLM {state.llmEnabled ? "ON" : "OFF"}
          </span>
        </div>
      </header>

      {/* Mode Tabs */}
      <nav className="flex gap-1 px-6 py-2 bg-[var(--background)] border-b border-[var(--border)]">
        {TAB_BUTTONS.map((tab) => (
          <button
            key={tab.mode}
            onClick={() => setMode(tab.mode)}
            className={`px-4 py-1.5 rounded text-sm font-medium transition-colors ${
              state.mode === tab.mode
                ? "bg-[var(--primary)] text-[var(--primary-foreground)]"
                : "text-[var(--muted-foreground)] hover:text-[var(--foreground)] hover:bg-[var(--secondary)]"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      {/* Error banner */}
      {state.error && (
        <div className="mx-6 mt-3 bg-red-950/40 border border-red-900 rounded px-4 py-2 text-sm text-red-200">
          {state.error}
        </div>
      )}

      {/* Content area */}
      <main className="flex-1 p-6 overflow-hidden">
        {state.mode === "builder" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 h-full">
            <div className="lg:col-span-2 h-full min-h-[500px]">
              <DagVisualizer
                capabilities={state.capabilities}
                onChange={(nodes, edges) => buildComposition(nodes, edges)}
                simulationValid={state.simulationReport?.dag_valid ?? null}
              />
            </div>
            <div className="h-full min-h-[500px]">
              <SimulationPanel
                report={state.simulationReport}
                onRun={runSimulation}
                onApprove={approveAndSubmit}
                loading={state.loading}
              />
            </div>
          </div>
        )}

        {state.mode === "chat" && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 h-full">
            <div className="h-full min-h-[500px]">
              <ChatPanel messages={state.chatMessages} onSend={sendChat} loading={state.loading} />
            </div>
            <div className="h-full min-h-[500px]">
              <SimulationPanel
                report={state.simulationReport}
                onRun={runSimulation}
                onApprove={approveAndSubmit}
                loading={state.loading}
              />
            </div>
          </div>
        )}

        {state.mode === "replay" && (
          <div className="h-full min-h-[500px]">
            <ReplayViewer />
          </div>
        )}

        {state.mode === "audit" && (
          <div className="h-full min-h-[500px]">
            <AuditLogViewer entries={state.auditEntries} total={state.auditEntries.length} />
          </div>
        )}

        {state.mode === "registry" && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 h-full">
            <div className="lg:col-span-1 h-full min-h-[500px]">
              <RegistryExplorer capabilities={state.capabilities} />
            </div>
            <div className="lg:col-span-2 h-full min-h-[500px]">
              <ComplianceDashboard quota={state.quota} />
            </div>
          </div>
        )}

        {state.mode === "compliance" && (
          <div className="h-full min-h-[500px]">
            <ComplianceDashboard quota={state.quota} />
          </div>
        )}
      </main>
    </div>
  );
}
