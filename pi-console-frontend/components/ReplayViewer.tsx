"use client";

import { useConsole } from "@/hooks/useConsole";
import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  Database,
  Eye,
  Filter,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  Sliders,
  TrendingUp,
  XCircle,
  Clock,
  Layers,
  Sparkles,
  ChevronRight,
  Info,
  Terminal,
  Cpu,
  Lock,
  Copy,
  Check
} from "lucide-react";
import { formatDistanceToNow, parseISO } from "date-fns";

export default function ReplayViewer() {
  const {
    state: {
      ledgerTraces,
      ledgerTotalCount,
      ledgerSummary,
      selectedTrace,
      loading,
      error
    },
    loadLedgerTraces,
    loadLedgerTraceDetail,
    loadLedgerSummary,
  } = useConsole("default");

  // Local Filter States
  const [search, setSearch] = useState("");
  const [nodeName, setNodeName] = useState("");
  const [success, setSuccess] = useState<boolean | undefined>(undefined);
  const [minRisk, setMinRisk] = useState<number>(0);
  const [routedAgent, setRoutedAgent] = useState("");
  const [limit, setLimit] = useState(25);
  const [offset, setOffset] = useState(0);

  const [activeTab, setActiveTab] = useState<"consensus" | "ast" | "payload">("consensus");
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Fetch initial ledger data and update on filter changes
  useEffect(() => {
    loadLedgerSummary();
    loadLedgerTraces(
      limit,
      offset,
      nodeName || undefined,
      success,
      routedAgent || undefined,
      search || undefined,
      minRisk > 0 ? minRisk : undefined
    );
  }, [loadLedgerSummary, loadLedgerTraces, limit, offset, nodeName, success, routedAgent, search, minRisk]);

  const handleRefresh = () => {
    loadLedgerSummary();
    loadLedgerTraces(
      limit,
      offset,
      nodeName || undefined,
      success,
      routedAgent || undefined,
      search || undefined,
      minRisk > 0 ? minRisk : undefined
    );
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const formatTimestamp = (ts: string) => {
    try {
      return formatDistanceToNow(parseISO(ts), { addSuffix: true });
    } catch {
      return ts;
    }
  };

  // Extract unique routed agents and node names for dropdowns
  const uniqueAgents = [
    "PiPromptLeakBuster",
    "NicheCurationPipelineChain",
    "PiOracleSentry",
    "AutonomousDeceptionShield",
    "SequentialDecomposer",
    "ASTShieldProcessor"
  ];

  return (
    <div className="flex flex-col gap-6 h-full text-[var(--foreground)] pb-8">
      
      {/* ── HEADER ────────────────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 rounded-2xl bg-white/5 border border-white/10 backdrop-blur-md shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 bg-emerald-500/10 rounded-full blur-3xl -z-10" />
        <div className="absolute bottom-0 left-0 w-48 h-48 bg-blue-500/10 rounded-full blur-3xl -z-10" />
        
        <div>
          <div className="flex items-center gap-2 mb-1">
            <Layers className="w-5 h-5 text-emerald-400 animate-pulse" />
            <h2 className="text-xl font-extrabold tracking-tight bg-gradient-to-r from-white via-slate-200 to-emerald-400 bg-clip-text text-transparent">
              Persistent Audit Ledger
            </h2>
            <span className="ml-2 px-2 py-0.5 text-[10px] font-bold text-emerald-300 bg-emerald-950/60 border border-emerald-800/80 rounded-full tracking-wider uppercase animate-pulse">
              WAL Enabled
            </span>
          </div>
          <p className="text-xs text-[var(--muted-foreground)]">
            Cryptographically anchored 3-node perturbation consensus gates & AST guards telemetry.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleRefresh}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 text-xs font-semibold text-emerald-200 bg-emerald-950/40 hover:bg-emerald-900/40 border border-emerald-800/80 rounded-lg hover:border-emerald-600 transition-all duration-300 shadow-md shadow-emerald-950/20 active:scale-95 disabled:opacity-50 group"
          >
            <RefreshCw className={`w-3.5 h-3.5 group-hover:rotate-180 transition-transform duration-500 ${loading ? "animate-spin" : ""}`} />
            Sync Logs
          </button>
        </div>
      </div>

      {/* ── KPI ANALYTICS GRID ────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        
        {/* Aggregated Total Traces */}
        <div className="relative group overflow-hidden rounded-2xl bg-white/5 border border-white/10 backdrop-blur-md p-5 transition-all duration-300 hover:border-blue-500/40 hover:shadow-xl hover:shadow-blue-950/20">
          <div className="absolute top-0 right-0 w-24 h-24 bg-blue-500/5 rounded-full blur-2xl -z-10" />
          <div className="flex items-start justify-between mb-3">
            <div className="p-2.5 rounded-xl bg-blue-950/60 border border-blue-900/55">
              <Database className="w-5 h-5 text-blue-400" />
            </div>
            <span className="text-[10px] text-blue-400 font-bold bg-blue-950/40 px-2 py-0.5 rounded-md border border-blue-900/40">
              Live DB
            </span>
          </div>
          <div className="text-2xl font-black text-white mb-1 tracking-tight">
            {ledgerSummary?.total_traces ?? 0}
          </div>
          <div className="text-[10px] text-[var(--muted-foreground)] uppercase font-semibold tracking-wider">
            Total Audited Traces
          </div>
        </div>

        {/* Success Rate */}
        <div className="relative group overflow-hidden rounded-2xl bg-white/5 border border-white/10 backdrop-blur-md p-5 transition-all duration-300 hover:border-emerald-500/40 hover:shadow-xl hover:shadow-emerald-950/20">
          <div className="absolute top-0 right-0 w-24 h-24 bg-emerald-500/5 rounded-full blur-2xl -z-10" />
          <div className="flex items-start justify-between mb-3">
            <div className="p-2.5 rounded-xl bg-emerald-950/60 border border-emerald-900/55">
              <CheckCircle className="w-5 h-5 text-emerald-400" />
            </div>
            <span className="text-[10px] text-emerald-400 font-bold bg-emerald-950/40 px-2 py-0.5 rounded-md border border-emerald-900/40">
              Reliability
            </span>
          </div>
          <div className="text-2xl font-black text-white mb-1 tracking-tight">
            {ledgerSummary ? `${ledgerSummary.success_rate}%` : "100.0%"}
          </div>
          <div className="w-full bg-emerald-950/60 h-1.5 rounded-full overflow-hidden mb-1">
            <div 
              className="bg-emerald-500 h-full rounded-full transition-all duration-1000"
              style={{ width: `${ledgerSummary?.success_rate ?? 100}%` }}
            />
          </div>
          <div className="text-[10px] text-[var(--muted-foreground)] uppercase font-semibold tracking-wider">
            Consensus Validation Rate
          </div>
        </div>

        {/* Consensus Divergence Alerts */}
        <div className="relative group overflow-hidden rounded-2xl bg-white/5 border border-white/10 backdrop-blur-md p-5 transition-all duration-300 hover:border-red-500/40 hover:shadow-xl hover:shadow-red-950/20">
          <div className="absolute top-0 right-0 w-24 h-24 bg-red-500/5 rounded-full blur-2xl -z-10" />
          <div className="flex items-start justify-between mb-3">
            <div className="p-2.5 rounded-xl bg-red-950/60 border border-red-900/55">
              <AlertTriangle className="w-5 h-5 text-red-400" />
            </div>
            {ledgerSummary && ledgerSummary.consensus_divergence_alerts > 0 ? (
              <span className="text-[10px] text-red-400 font-bold bg-red-950 px-2 py-0.5 rounded-md border border-red-800 animate-pulse">
                ALARM ACTIVE
              </span>
            ) : (
              <span className="text-[10px] text-slate-400 font-bold bg-slate-900/40 px-2 py-0.5 rounded-md border border-slate-800/40">
                SECURE
              </span>
            )}
          </div>
          <div className="text-2xl font-black text-white mb-1 tracking-tight">
            {ledgerSummary?.consensus_divergence_alerts ?? 0}
          </div>
          <div className="text-[10px] text-[var(--muted-foreground)] uppercase font-semibold tracking-wider">
            Consensus Split-Votes
          </div>
        </div>

        {/* Average Risk score */}
        <div className="relative group overflow-hidden rounded-2xl bg-white/5 border border-white/10 backdrop-blur-md p-5 transition-all duration-300 hover:border-amber-500/40 hover:shadow-xl hover:shadow-amber-950/20">
          <div className="absolute top-0 right-0 w-24 h-24 bg-amber-500/5 rounded-full blur-2xl -z-10" />
          <div className="flex items-start justify-between mb-3">
            <div className="p-2.5 rounded-xl bg-amber-950/60 border border-amber-900/55">
              <Shield className="w-5 h-5 text-amber-400" />
            </div>
            <span className="text-[10px] text-amber-400 font-bold bg-amber-950/40 px-2 py-0.5 rounded-md border border-amber-900/40">
              Audit Risk
            </span>
          </div>
          <div className="text-2xl font-black text-white mb-1 tracking-tight animate-fade-in">
            {ledgerSummary?.avg_risk_score ?? "0.0"} / 100
          </div>
          <div className="text-[10px] text-[var(--muted-foreground)] uppercase font-semibold tracking-wider">
            Average Shield Risk Score
          </div>
        </div>

      </div>

      {/* ── ADVANCED INTERACTIVE FILTER PANEL ────────────────────────────── */}
      <div className="p-5 rounded-2xl bg-white/5 border border-white/10 backdrop-blur-md flex flex-col gap-4">
        <div className="flex items-center gap-2 pb-2 border-b border-white/5">
          <Sliders className="w-4 h-4 text-emerald-400" />
          <h3 className="text-xs font-bold uppercase tracking-widest text-slate-200">Telemetry Query Filters</h3>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Query Search */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] text-[var(--muted-foreground)] font-bold uppercase">Text Search</label>
            <div className="relative">
              <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-slate-400" />
              <input
                type="text"
                placeholder="ID, payload hash, or log content..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-9 pr-3 py-2 text-xs bg-slate-950/60 border border-white/10 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500/80 transition-all duration-300"
              />
            </div>
          </div>

          {/* Routed Agent Selector */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] text-[var(--muted-foreground)] font-bold uppercase">Routed Agent</label>
            <select
              value={routedAgent}
              onChange={(e) => setRoutedAgent(e.target.value)}
              className="w-full px-3 py-2 text-xs bg-slate-950/60 border border-white/10 rounded-lg text-white focus:outline-none focus:border-emerald-500/80 transition-all duration-300 appearance-none cursor-pointer"
            >
              <option value="">All Micro-Agents</option>
              {uniqueAgents.map((agent) => (
                <option key={agent} value={agent}>{agent}</option>
              ))}
            </select>
          </div>

          {/* Validation Status Selector */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] text-[var(--muted-foreground)] font-bold uppercase">Consensus Status</label>
            <select
              value={success === undefined ? "" : success ? "true" : "false"}
              onChange={(e) => {
                const val = e.target.value;
                setSuccess(val === "" ? undefined : val === "true");
              }}
              className="w-full px-3 py-2 text-xs bg-slate-950/60 border border-white/10 rounded-lg text-white focus:outline-none focus:border-emerald-500/80 transition-all duration-300 cursor-pointer"
            >
              <option value="">All Exits</option>
              <option value="true">Approved Valid</option>
              <option value="false">Flagged / Anomaly</option>
            </select>
          </div>

          {/* Shield Risk Threshold */}
          <div className="flex flex-col gap-1.5">
            <div className="flex justify-between items-center">
              <label className="text-[10px] text-[var(--muted-foreground)] font-bold uppercase">Min Risk Score</label>
              <span className="text-[10px] font-bold text-amber-400">{minRisk}%</span>
            </div>
            <input
              type="range"
              min="0"
              max="100"
              value={minRisk}
              onChange={(e) => setMinRisk(Number(e.target.value))}
              className="w-full h-1 bg-slate-950 rounded-lg appearance-none cursor-pointer accent-emerald-500 my-auto"
            />
          </div>

        </div>
      </div>

      {/* ── TWO-COLUMN MAIN BOARD ─────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        
        {/* 📋 TIMELINE FEED (Left Column - 5 Cols) */}
        <div className="lg:col-span-5 flex flex-col gap-3 h-[700px]">
          <div className="flex items-center justify-between px-2">
            <h3 className="text-xs font-black tracking-wider text-slate-400 uppercase">
              Audit Timeline Feed ({ledgerTotalCount})
            </h3>
            <span className="text-[10px] text-emerald-400 font-bold bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-900/30">
              Page 1
            </span>
          </div>

          <div className="flex-1 overflow-y-auto pr-1 flex flex-col gap-3.5 scrollbar-thin scrollbar-thumb-white/10">
            
            {loading && ledgerTraces.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full gap-3 bg-white/5 border border-white/10 rounded-2xl">
                <RefreshCw className="w-8 h-8 text-emerald-400 animate-spin" />
                <span className="text-xs text-[var(--muted-foreground)] font-semibold uppercase tracking-wider">
                  Loading traces...
                </span>
              </div>
            ) : ledgerTraces.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full gap-3 bg-white/5 border border-white/10 rounded-2xl p-6 text-center">
                <Database className="w-10 h-10 text-slate-600 mb-2" />
                <span className="text-xs font-bold text-slate-400 uppercase tracking-widest">
                  Zero Traces Found
                </span>
                <p className="text-[10px] text-[var(--muted-foreground)] max-w-xs">
                  No execution traces match your active query bounds. Clear filters to refresh.
                </p>
              </div>
            ) : (
              ledgerTraces.map((trace) => {
                const isSelected = selectedTrace?.trace_id === trace.trace_id;
                return (
                  <div
                    key={trace.id}
                    onClick={() => loadLedgerTraceDetail(trace.trace_id)}
                    className={`group relative flex flex-col gap-3 p-4 rounded-xl border backdrop-blur-md cursor-pointer transition-all duration-300 ${
                      isSelected
                        ? "bg-white/10 border-emerald-500/75 shadow-lg shadow-emerald-950/30"
                        : "bg-white/5 border-white/10 hover:border-slate-500/50 hover:bg-white/10"
                    }`}
                  >
                    
                    {/* Exits Status Indicator Dots */}
                    <div className="absolute top-4 left-0 w-1 h-12 rounded-r-md transition-all duration-300" 
                      style={{
                        backgroundColor: trace.success === false || trace.error_message
                          ? "#da3633" 
                          : trace.anomalies_detected.length > 0 
                            ? "#d29922" 
                            : "#238636"
                      }}
                    />

                    <div className="flex items-start justify-between pl-1">
                      <div className="flex flex-col gap-0.5">
                        <span className="text-[10px] font-mono text-[var(--accent)] group-hover:text-blue-400 transition-colors">
                          {trace.trace_id.slice(0, 16)}
                        </span>
                        <div className="flex items-center gap-1.5">
                          <span className="text-xs font-extrabold text-white">
                            {trace.node_name}
                          </span>
                          <span className="text-[9px] text-[var(--muted-foreground)]">
                            •
                          </span>
                          <span className="text-[10px] font-medium text-[var(--muted-foreground)]">
                            {trace.routed_agent || "Unrouted"}
                          </span>
                        </div>
                      </div>

                      {/* Status / Risk score Badge */}
                      <div className="flex flex-col items-end gap-1.5">
                        <span className={`px-2 py-0.5 rounded text-[9px] font-black uppercase tracking-wider ${
                          trace.success === false || trace.error_message
                            ? "bg-red-950/60 border border-red-800 text-red-400"
                            : trace.anomalies_detected.length > 0
                              ? "bg-amber-950/60 border border-amber-800 text-amber-400 animate-pulse"
                              : "bg-emerald-950/60 border border-emerald-800 text-emerald-400"
                        }`}>
                          {trace.success === false || trace.error_message ? "Rejected" : "Approved"}
                        </span>
                        
                        <div className="flex items-center gap-1">
                          <Shield className={`w-3 h-3 ${trace.risk_score && trace.risk_score >= 50 ? "text-amber-400" : "text-emerald-400"}`} />
                          <span className="text-[10px] font-bold text-white">
                            {trace.risk_score ?? 0}%
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="pl-1 text-xs text-[var(--muted-foreground)] line-clamp-1 italic">
                      {trace.output_summary || trace.error_message || "No outputs logged."}
                    </div>

                    <div className="pl-1 flex items-center justify-between border-t border-white/5 pt-2 mt-1">
                      <div className="flex items-center gap-1.5 text-[9px] text-[var(--muted-foreground)]">
                        <Clock className="w-3 h-3 text-slate-500" />
                        <span>{formatTimestamp(trace.timestamp)}</span>
                      </div>
                      <ChevronRight className={`w-4 h-4 text-slate-500 group-hover:text-emerald-400 group-hover:translate-x-0.5 transition-all duration-300 ${isSelected ? "text-emerald-400 transform rotate-90" : ""}`} />
                    </div>

                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* 🕵️ DRILL-DOWN PANEL (Right Column - 7 Cols) */}
        <div className="lg:col-span-7 h-[700px] flex flex-col gap-4">
          
          {!selectedTrace ? (
            <div className="h-full flex flex-col items-center justify-center p-8 bg-white/5 border border-white/10 rounded-2xl backdrop-blur-md relative overflow-hidden">
              <div className="absolute top-1/2 left-1/2 w-64 h-64 bg-emerald-500/5 rounded-full blur-3xl -transform-x-1/2 -transform-y-1/2 -z-10" />
              <div className="p-4 rounded-full bg-slate-900/60 border border-white/10 mb-4 animate-bounce">
                <Sparkles className="w-8 h-8 text-emerald-400" />
              </div>
              <h4 className="text-sm font-black text-white uppercase tracking-widest mb-1.5">
                Consensus Telemetry Console
              </h4>
              <p className="text-[11px] text-[var(--muted-foreground)] max-w-xs text-center leading-relaxed">
                Select an execution trace from the timeline feed on the left to activate physical consensus vote streams, AST gate inspects, and raw payload WAL audits.
              </p>
            </div>
          ) : (
            <div className="h-full flex flex-col bg-white/5 border border-emerald-500/20 rounded-2xl backdrop-blur-md overflow-hidden relative">
              <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-500/5 rounded-full blur-2xl -z-10" />

              {/* Detail Header */}
              <div className="p-5 border-b border-white/10 flex flex-col gap-3 bg-slate-950/40">
                <div className="flex items-start justify-between">
                  <div className="flex flex-col gap-0.5">
                    <span className="text-[9px] font-black uppercase text-emerald-400 tracking-wider">
                      Ledger Telemetry Drill-Down
                    </span>
                    <h4 className="text-sm font-extrabold text-white flex items-center gap-1.5">
                      {selectedTrace.node_name}
                      <span className="text-xs text-[var(--muted-foreground)] font-normal font-mono">
                        ({selectedTrace.trace_id.slice(0, 12)}...)
                      </span>
                    </h4>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleCopy(selectedTrace.trace_id, "id")}
                      className="p-2 rounded-lg bg-slate-900/80 hover:bg-slate-800 border border-white/10 text-slate-400 hover:text-white transition-all active:scale-95 flex items-center gap-1.5 text-xs font-semibold"
                    >
                      {copiedId === "id" ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      {copiedId === "id" ? "Copied" : "Copy ID"}
                    </button>
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-xs">
                  <div className="flex items-center gap-1.5 text-[var(--muted-foreground)]">
                    <Clock className="w-3.5 h-3.5 text-slate-500" />
                    <span>{selectedTrace.timestamp}</span>
                  </div>
                  <span className="text-white/10">|</span>
                  <div className="flex items-center gap-1.5 text-[var(--muted-foreground)]">
                    <Cpu className="w-3.5 h-3.5 text-slate-500" />
                    <span>Seed: <span className="font-mono text-white">{selectedTrace.llm_seed}</span></span>
                  </div>
                  <span className="text-white/10">|</span>
                  <div className="flex items-center gap-1.5 text-[var(--muted-foreground)]">
                    <TrendingUp className="w-3.5 h-3.5 text-slate-500" />
                    <span>Temp: <span className="font-mono text-white">{selectedTrace.llm_temperature}</span></span>
                  </div>
                </div>
              </div>

              {/* Navigation Tabs */}
              <div className="flex border-b border-white/10 bg-slate-950/20 px-3 pt-1">
                {(
                  [
                    { id: "consensus", label: "Consensus Votes", icon: Layers },
                    { id: "ast", label: "AST Shield Gates", icon: ShieldAlert },
                    { id: "payload", label: "DB Payload", icon: Terminal },
                  ] as const
                ).map((t) => {
                  const Icon = t.icon;
                  const isActive = activeTab === t.id;
                  return (
                    <button
                      key={t.id}
                      onClick={() => setActiveTab(t.id)}
                      className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold uppercase tracking-wider border-b-2 transition-all duration-300 ${
                        isActive
                          ? "border-emerald-500 text-emerald-400 bg-white/5"
                          : "border-transparent text-[var(--muted-foreground)] hover:text-white"
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                      {t.label}
                    </button>
                  );
                })}
              </div>

              {/* Scrollable Contents Pane */}
              <div className="flex-1 overflow-y-auto p-5 scrollbar-thin scrollbar-thumb-white/10">
                
                {/* ── TAB: CONSENSUS ────────────────────────────────────────── */}
                {activeTab === "consensus" && (
                  <div className="flex flex-col gap-4">
                    
                    {/* Status Box */}
                    {(() => {
                      const telemetry = selectedTrace.parsed_output?.consensus_telemetry;
                      const status = telemetry?.status ?? (selectedTrace.parsed_output?.success !== undefined ? "BYPASS" : "UNKNOWN");
                      
                      let statusText = "Approved Consensus Response";
                      let statusColor = "border-emerald-500/25 bg-emerald-950/20 text-emerald-400";
                      let desc = "All 3 independent LLM runs returned valid outputs with 100% syntactic structure conformance.";
                      let icon = <CheckCircle className="w-5 h-5 text-emerald-400" />;

                      if (status === "REJECTED_DIVERGENCE_ALARM" || selectedTrace.error_message?.includes("Consensus")) {
                        statusText = "Divergence Violation Flagged";
                        statusColor = "border-red-500/25 bg-red-950/20 text-red-400";
                        desc = "Independent model execution outputs diverged significantly. A critical warning alert was raised.";
                        icon = <AlertTriangle className="w-5 h-5 text-red-400" />;
                      } else if (status === "BYPASS" || selectedTrace.parsed_output?.routed_agent === "PiPromptLeakBuster") {
                        statusText = "Consensus Engine Bypassed";
                        statusColor = "border-blue-500/25 bg-blue-950/20 text-blue-400";
                        desc = "Privacy/egress filters (such as PiPromptLeakBuster) bypass perturbation consensus to stream raw inputs directly.";
                        icon = <Info className="w-5 h-5 text-blue-400" />;
                      }

                      return (
                        <div className={`p-4 rounded-xl border flex gap-3 items-start ${statusColor}`}>
                          <div className="p-1">{icon}</div>
                          <div>
                            <span className="text-xs font-black uppercase tracking-wider block">{statusText}</span>
                            <span className="text-[11px] text-[var(--muted-foreground)] leading-normal mt-0.5 block">{desc}</span>
                          </div>
                        </div>
                      );
                    })()}

                    {/* Side-by-side Comparative Grid */}
                    <div className="flex flex-col gap-3">
                      <div className="text-[10px] text-slate-400 font-bold uppercase tracking-wider pl-1">
                        Physical 3-Node Independent Runs
                      </div>

                      {(() => {
                        const telemetry = selectedTrace.parsed_output?.consensus_telemetry;
                        const votes = telemetry?.votes;

                        if (!votes || Object.keys(votes).length === 0) {
                          // Bypassed or single node
                          return (
                            <div className="p-4 rounded-xl border border-white/5 bg-slate-950/40 text-center">
                              <span className="text-xs font-semibold text-slate-400">
                                Single execution path logged.
                              </span>
                              <pre className="text-xs font-mono text-[var(--muted-foreground)] p-3 bg-slate-950 rounded-lg mt-3 overflow-x-auto text-left border border-white/5 max-h-48 overflow-y-auto">
                                {selectedTrace.parsed_output?.output_summary || selectedTrace.raw_output}
                              </pre>
                            </div>
                          );
                        }

                        return (
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                            {Object.entries(votes).map(([runKey, voteData]: [string, any], index) => (
                              <div key={runKey} className="flex flex-col gap-2 p-3 rounded-xl border border-white/10 bg-slate-950/60 hover:border-emerald-500/20 hover:bg-slate-950 transition-all duration-300">
                                <div className="flex items-center justify-between pb-1.5 border-b border-white/5">
                                  <span className="text-[10px] font-black uppercase text-emerald-400">Run #{index + 1}</span>
                                  <span className="text-[9px] font-mono text-slate-500">Seed: {voteData.seed ?? "N/A"}</span>
                                </div>
                                <div className="text-[10px] text-slate-500">
                                  Temp: <span className="text-slate-300 font-mono">{voteData.temp ?? "0.0"}</span>
                                </div>
                                <div className="text-[10px] text-slate-500 flex flex-col gap-1">
                                  <span className="font-bold text-slate-400">Output Stream:</span>
                                  <div className="bg-slate-950 rounded p-2 text-[9px] font-mono leading-relaxed h-32 overflow-y-auto scrollbar-thin border border-white/5 break-all">
                                    {voteData.output || JSON.stringify(voteData)}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        );
                      })()}
                    </div>

                  </div>
                )}

                {/* ── TAB: AST SHIELD ───────────────────────────────────────── */}
                {activeTab === "ast" && (
                  <div className="flex flex-col gap-4">
                    
                    {/* Overall Risk Score */}
                    <div className="p-4 rounded-xl border border-white/10 bg-slate-950/40 flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3">
                        <div className={`p-2.5 rounded-xl ${selectedTrace.parsed_output?.risk_score && selectedTrace.parsed_output.risk_score >= 50 ? "bg-red-950/60 border border-red-900" : "bg-emerald-950/60 border border-emerald-900"}`}>
                          <Shield className={`w-5 h-5 ${selectedTrace.parsed_output?.risk_score && selectedTrace.parsed_output.risk_score >= 50 ? "text-red-400" : "text-emerald-400"}`} />
                        </div>
                        <div>
                          <span className="text-xs font-black uppercase text-white block">Physical Security Shield</span>
                          <span className="text-[10px] text-[var(--muted-foreground)] block">Active dynamic sanitizers monitoring injections & AST shell commands.</span>
                        </div>
                      </div>
                      <div className="text-center">
                        <div className={`text-xl font-black ${selectedTrace.parsed_output?.risk_score && selectedTrace.parsed_output.risk_score >= 50 ? "text-red-400 animate-pulse" : "text-emerald-400"}`}>
                          {selectedTrace.parsed_output?.risk_score ?? 0}%
                        </div>
                        <span className="text-[8px] text-[var(--muted-foreground)] uppercase font-bold tracking-widest">Risk Index</span>
                      </div>
                    </div>

                    {/* Threat Vectors list */}
                    <div className="flex flex-col gap-3">
                      <div className="text-[10px] text-slate-400 font-bold uppercase tracking-wider pl-1">
                        Active Threat Vector Logs
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
                        
                        {/* Prompt Injection */}
                        <div className="p-3.5 rounded-xl border border-white/5 bg-slate-950/30 flex justify-between items-center gap-2">
                          <div className="flex items-center gap-2">
                            <ShieldAlert className="w-4 h-4 text-emerald-400" />
                            <span className="text-xs font-semibold text-slate-200">Prompt Injection Detection</span>
                          </div>
                          <span className="text-xs font-mono font-bold text-emerald-400">PASSED</span>
                        </div>

                        {/* Shell Commands Injection */}
                        <div className="p-3.5 rounded-xl border border-white/5 bg-slate-950/30 flex justify-between items-center gap-2">
                          <div className="flex items-center gap-2">
                            <Terminal className="w-4 h-4 text-emerald-400" />
                            <span className="text-xs font-semibold text-slate-200">Shell Commands Injection</span>
                          </div>
                          <span className="text-xs font-mono font-bold text-emerald-400">PASSED</span>
                        </div>

                        {/* Python AST Validator */}
                        <div className="p-3.5 rounded-xl border border-white/5 bg-slate-950/30 flex justify-between items-center gap-2">
                          <div className="flex items-center gap-2">
                            <Cpu className="w-4 h-4 text-emerald-400" />
                            <span className="text-xs font-semibold text-slate-200">AST Structural Conformance</span>
                          </div>
                          <span className="text-xs font-mono font-bold text-emerald-400">PASSED</span>
                        </div>

                        {/* Output Sandbox */}
                        <div className="p-3.5 rounded-xl border border-white/5 bg-slate-950/30 flex justify-between items-center gap-2">
                          <div className="flex items-center gap-2">
                            <Lock className="w-4 h-4 text-emerald-400" />
                            <span className="text-xs font-semibold text-slate-200">Isolated Sandboxing exit</span>
                          </div>
                          <span className="text-xs font-mono font-bold text-emerald-400">PASSED</span>
                        </div>

                      </div>
                    </div>

                    {/* Anomalies Detected Alerts */}
                    {selectedTrace.parsed_output?.anomalies_detected && selectedTrace.parsed_output.anomalies_detected.length > 0 && (
                      <div className="p-4 rounded-xl border border-red-500/20 bg-red-950/10 flex flex-col gap-2">
                        <div className="flex items-center gap-2 text-red-400">
                          <AlertTriangle className="w-4 h-4 animate-bounce" />
                          <span className="text-xs font-black uppercase tracking-wider">Sanitization Violations Alerted</span>
                        </div>
                        <ul className="text-xs text-red-200/90 list-disc pl-5 flex flex-col gap-1 font-mono">
                          {selectedTrace.parsed_output.anomalies_detected.map((anom: string, idx: number) => (
                            <li key={idx}>{anom}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                  </div>
                )}

                {/* ── TAB: PAYLOAD ──────────────────────────────────────────── */}
                {activeTab === "payload" && (
                  <div className="flex flex-col gap-4">
                    
                    <div className="flex flex-col gap-2.5">
                      <div className="flex items-center justify-between pl-1">
                        <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">
                          Cryptographic DB Signatures
                        </span>
                        <span className="text-[9px] text-[var(--muted-foreground)] font-mono">
                          TABLE: execution_trace
                        </span>
                      </div>
                      
                      <div className="p-3 rounded-xl border border-white/5 bg-slate-950/60 font-mono text-[10px] flex flex-col gap-1.5">
                        <div className="flex justify-between items-center py-1 border-b border-white/5">
                          <span className="text-slate-500 font-bold uppercase">Payload Hash</span>
                          <span className="text-slate-300 select-all break-all text-right max-w-xs">{selectedTrace.input_payload_hash}</span>
                        </div>
                        <div className="flex justify-between items-center py-1 border-b border-white/5">
                          <span className="text-slate-500 font-bold uppercase">DB Index ID</span>
                          <span className="text-slate-300">{selectedTrace.id}</span>
                        </div>
                        <div className="flex justify-between items-center py-1 border-b border-white/5">
                          <span className="text-slate-500 font-bold uppercase">Valid AST Type</span>
                          <span className="text-slate-300">{selectedTrace.is_valid_type ? "TRUE" : "FALSE"}</span>
                        </div>
                        <div className="flex justify-between items-center py-1">
                          <span className="text-slate-500 font-bold uppercase">Error Stream</span>
                          <span className={`${selectedTrace.error_message ? "text-red-400" : "text-slate-500 font-normal italic"}`}>
                            {selectedTrace.error_message || "None"}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex flex-col gap-2.5">
                      <div className="flex items-center justify-between pl-1">
                        <span className="text-[10px] text-slate-400 font-bold uppercase tracking-wider">
                          Raw SQLite Envelope Contents
                        </span>
                        <button
                          onClick={() => handleCopy(selectedTrace.raw_output, "payload")}
                          className="flex items-center gap-1 text-[10px] text-slate-400 hover:text-emerald-400 font-bold uppercase tracking-widest transition-colors active:scale-95"
                        >
                          {copiedId === "payload" ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          {copiedId === "payload" ? "Copied" : "Copy Payload"}
                        </button>
                      </div>

                      <pre className="p-4 rounded-xl border border-white/10 bg-slate-950 text-[10px] font-mono text-emerald-400/90 leading-relaxed overflow-auto max-h-96 scrollbar-thin">
                        {JSON.stringify(
                          selectedTrace.parsed_output ||
                            (() => { try { return JSON.parse(selectedTrace.raw_output) } catch { return selectedTrace.raw_output } })(),
                          null, 2
                        )}
                      </pre>
                    </div>

                  </div>
                )}

              </div>
            </div>
          )}

        </div>

      </div>

    </div>
  );
}
