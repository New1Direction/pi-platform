"use client";

import { useEffect, useState } from "react";
import { useConsole } from "@/hooks/useConsole";
import DagVisualizer from "@/components/DagVisualizer";
import SimulationPanel from "@/components/SimulationPanel";
import ChatPanel from "@/components/ChatPanel";
import ReplayViewer from "@/components/ReplayViewer";
import AuditLogViewer from "@/components/AuditLogViewer";
import RegistryExplorer from "@/components/RegistryExplorer";
import ComplianceDashboard from "@/components/ComplianceDashboard";

import {
  MessageSquare,
  Network,
  RotateCcw,
  FileSpreadsheet,
  Layers,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  Cpu,
  Shield,
  Activity,
  User,
  Settings,
  AlertTriangle,
  Server,
  Fingerprint,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

type ModeType = ReturnType<typeof useConsole>["state"]["mode"];

interface TabButton {
  mode: ModeType;
  label: string;
  icon: LucideIcon;
}

const TAB_BUTTONS: TabButton[] = [
  { mode: "chat", label: "Security Copilot", icon: MessageSquare },
  { mode: "builder", label: "Composition Builder", icon: Network },
  { mode: "replay", label: "Ledger Replay", icon: RotateCcw },
  { mode: "audit", label: "Security Audit Log", icon: FileSpreadsheet },
  { mode: "registry", label: "Capabilities Catalog", icon: Layers },
  { mode: "compliance", label: "Policy Compliance", icon: ShieldCheck },
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

  const [sidebarExpanded, setSidebarExpanded] = useState(true);

  // Mock consensus nodes state for visualization
  const [consensusNodes, setConsensusNodes] = useState([
    { name: "Node Alpha", status: "active" },
    { name: "Node Beta", status: "processing" },
    { name: "Node Gamma", status: "active" },
    { name: "Node Delta", status: "idle" },
    { name: "Node Epsilon", status: "processing" },
  ]);

  useEffect(() => {
    initSession();
    loadCapabilities();
    loadQuota();
  }, [initSession, loadCapabilities, loadQuota]);

  useEffect(() => {
    if (state.mode === "audit") loadAuditLog();
    if (state.mode === "compliance") loadQuota();
  }, [state.mode, loadAuditLog, loadQuota]);

  // Periodic visual simulation of consensus nodes state
  useEffect(() => {
    const interval = setInterval(() => {
      setConsensusNodes((nodes) =>
        nodes.map((node) => {
          const rand = Math.random();
          let status = node.status;
          if (rand < 0.15) {
            status = "processing";
          } else if (rand < 0.3) {
            status = "active";
          } else if (rand < 0.4) {
            status = "idle";
          }
          return { ...node, status };
        })
      );
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen flex bg-[#09090b] text-[#f4f4f5] relative overflow-hidden">
      {/* Sidebar Navigation */}
      <aside
        className={`glass-panel m-4 mr-0 flex flex-col justify-between transition-all duration-300 ease-in-out z-10 ${
          sidebarExpanded ? "w-64" : "w-20"
        }`}
      >
        <div>
          {/* Brand/Logo */}
          <div className="p-4 flex items-center gap-3 border-b border-[var(--border)] overflow-hidden">
            <div className="p-2 bg-[var(--primary)]/10 text-[var(--primary)] rounded-lg">
              <Shield className="w-6 h-6 animate-pulse" />
            </div>
            {sidebarExpanded && (
              <div className="flex flex-col">
                <span className="font-bold tracking-wider text-sm text-[var(--primary)]">PI PLATFORM</span>
                <span className="text-[10px] text-[var(--muted-foreground)] tracking-tight">Security Copilot</span>
              </div>
            )}
          </div>

          {/* Navigation Links */}
          <nav className="p-3 flex flex-col gap-1">
            {TAB_BUTTONS.map((tab) => {
              const Icon = tab.icon;
              const isActive = state.mode === tab.mode;
              return (
                <button
                  key={tab.mode}
                  onClick={() => setMode(tab.mode)}
                  title={tab.label}
                  aria-label={tab.label}
                  aria-current={isActive ? "page" : undefined}
                  className={`w-full flex items-center gap-3 px-3 py-3 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? "bg-[var(--primary)]/15 text-[var(--primary)] border-l-2 border-[var(--primary)]"
                      : "text-[var(--muted-foreground)] hover:text-[var(--foreground)] hover:bg-[var(--secondary)]"
                  }`}
                >
                  <Icon className="w-5 h-5 shrink-0" aria-hidden="true" />
                  {sidebarExpanded && (
                    <span className="truncate transition-opacity duration-200">{tab.label}</span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Collapsible toggle & session footer */}
        <div className="p-3 border-t border-[var(--border)] flex flex-col gap-3">
          {sidebarExpanded && (
            <div className="p-3 bg-[var(--secondary)] rounded-lg text-[10px] text-[var(--muted-foreground)] flex flex-col gap-1">
              <div className="flex items-center justify-between">
                <span>Tenant ID:</span>
                <span className="font-mono text-white">{state.tenantId}</span>
              </div>
              <div className="flex items-center justify-between">
                <span>Session:</span>
                <span className="font-mono text-white" title={state.sessionId}>
                  {state.sessionId.slice(0, 10)}...
                </span>
              </div>
            </div>
          )}

          <button
            onClick={() => setSidebarExpanded(!sidebarExpanded)}
            aria-label={sidebarExpanded ? "Collapse sidebar" : "Expand sidebar"}
            aria-expanded={sidebarExpanded}
            className="w-full flex items-center justify-center p-2 rounded-lg bg-[var(--secondary)] hover:bg-[var(--border)] transition-colors text-[var(--muted-foreground)]"
          >
            {sidebarExpanded ? <ChevronLeft className="w-5 h-5" aria-hidden="true" /> : <ChevronRight className="w-5 h-5" aria-hidden="true" />}
          </button>
        </div>
      </aside>

      {/* Main Panel */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Header */}
        <header className="glass-panel m-4 mb-0 p-4 flex flex-col md:flex-row md:items-center md:justify-between gap-4 z-10">
          <div className="flex items-center gap-3">
            <Activity className="w-5 h-5 text-[var(--primary)] animate-spin [animation-duration:10s]" />
            <h1 className="text-base font-semibold tracking-tight text-white">
              {TAB_BUTTONS.find((t) => t.mode === state.mode)?.label ?? "Security Dashboard"}
            </h1>
            <span className="text-[10px] text-[var(--muted-foreground)] border border-[var(--border)] bg-zinc-900/60 rounded px-2 py-0.5 uppercase tracking-wider">
              Layer 4 Interface
            </span>
          </div>

          {/* Consensus Node Monitor Status */}
          <div className="flex items-center gap-3 bg-zinc-950/60 border border-[var(--border)] px-4 py-2 rounded-lg text-xs">
            <div className="flex items-center gap-1.5 mr-2">
              <Cpu className="w-4 h-4 text-[var(--primary)]" />
              <span className="font-medium text-[var(--muted-foreground)]">Consensus Cluster:</span>
            </div>
            <div className="flex items-center gap-4">
              {consensusNodes.map((node) => (
                <div key={node.name} className="flex items-center gap-1.5" title={`${node.name} is ${node.status}`}>
                  <span
                    className={`pulse-glow-node ${
                      node.status === "active" ? "active" : node.status === "processing" ? "processing" : "idle"
                    }`}
                  />
                  <span className="text-[10px] font-mono text-zinc-400 hidden lg:inline">{node.name.split(" ")[1]}</span>
                </div>
              ))}
            </div>
            <span
              className={`ml-2 px-2 py-0.5 rounded text-[10px] font-bold ${
                state.llmEnabled ? "bg-[var(--primary)]/20 text-[var(--primary)]" : "bg-zinc-800 text-zinc-500"
              }`}
            >
              LLM {state.llmEnabled ? "ACTIVE" : "BYPASSED"}
            </span>
          </div>
        </header>

        {/* Error banner */}
        {state.error && (
          <div className="mx-4 mt-4 bg-red-950/30 border border-red-500/20 rounded-lg p-4 text-sm text-red-200 flex items-start gap-3 backdrop-blur-md">
            <AlertTriangle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <span className="font-semibold text-red-300">System Warning:</span>
              <p className="text-red-300/80 mt-1 font-mono text-xs">{state.error}</p>
            </div>
          </div>
        )}

        {/* Main Content Area */}
        <main className="flex-1 p-4 overflow-hidden relative">
          {state.mode === "chat" && (
            <div className="h-full max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-4 overflow-hidden">
              {/* Glassmorphic Chatbot Terminal in max-w-3xl layout */}
              <div className="lg:col-span-2 h-full max-w-3xl w-full mx-auto overflow-hidden">
                <ChatPanel messages={state.chatMessages} onSend={sendChat} loading={state.loading} />
              </div>
              
              {/* Simulation feedback companion */}
              <div className="h-full overflow-hidden hidden lg:block">
                <SimulationPanel
                  report={state.simulationReport}
                  onRun={runSimulation}
                  onApprove={approveAndSubmit}
                  loading={state.loading}
                />
              </div>
            </div>
          )}

          {state.mode === "builder" && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 h-full">
              <div className="lg:col-span-2 h-full min-h-[450px]">
                <DagVisualizer
                  capabilities={state.capabilities}
                  onChange={(nodes, edges) => buildComposition(nodes, edges)}
                  simulationValid={state.simulationReport?.dag_valid ?? null}
                />
              </div>
              <div className="h-full min-h-[450px]">
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
            <div className="h-full overflow-hidden">
              <ReplayViewer />
            </div>
          )}

          {state.mode === "audit" && (
            <div className="h-full overflow-hidden">
              <AuditLogViewer entries={state.auditEntries} total={state.auditEntries.length} />
            </div>
          )}

          {state.mode === "registry" && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 h-full">
              <div className="lg:col-span-1 h-full min-h-[450px] overflow-hidden">
                <RegistryExplorer capabilities={state.capabilities} />
              </div>
              <div className="lg:col-span-2 h-full min-h-[450px] overflow-hidden">
                <ComplianceDashboard quota={state.quota} />
              </div>
            </div>
          )}

          {state.mode === "compliance" && (
            <div className="h-full overflow-hidden">
              <ComplianceDashboard quota={state.quota} />
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
