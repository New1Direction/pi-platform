"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  ExplicitCompositionRequest,
  CompositionNode,
  CompositionEdge,
  SimulationReport,
  MarketplaceCapability,
  CompatibilityNode,
  CompatibilityEdge,
  AuditLogEntry,
  TenantQuotaStatus,
  TraceListItem,
  TraceDetailResponse,
  LedgerSummaryResponse,
} from "@/types";
import {
  simulateComposition,
  submitComposition,
  translateChat,
  listCapabilities,
  getCompatibilityGraph,
  getAuditLog,
  getTenantQuota,
  createSession,
  setTenantId,
  getLedgerTraces,
  getLedgerTraceDetail,
  getLedgerSummary,
} from "@/lib/api";

export type ConsoleMode = "chat" | "builder" | "replay" | "audit" | "registry" | "compliance";

export interface ConsoleState {
  tenantId: string;
  sessionId: string;
  mode: ConsoleMode;
  llmEnabled: boolean;
  composition: ExplicitCompositionRequest | null;
  simulationReport: SimulationReport | null;
  capabilities: MarketplaceCapability[];
  compatNodes: CompatibilityNode[];
  compatEdges: CompatibilityEdge[];
  auditEntries: AuditLogEntry[];
  quota: TenantQuotaStatus | null;
  chatMessages: { role: "user" | "assistant"; text: string }[];
  loading: boolean;
  error: string | null;
  ledgerTraces: TraceListItem[];
  ledgerTotalCount: number;
  ledgerSummary: LedgerSummaryResponse | null;
  selectedTrace: TraceDetailResponse | null;
}

export function useConsole(tenantId: string, llmEnabled = false) {
  const [state, setState] = useState<ConsoleState>({
    tenantId,
    sessionId: "",
    mode: "builder",
    llmEnabled,
    composition: null,
    simulationReport: null,
    capabilities: [],
    compatNodes: [],
    compatEdges: [],
    auditEntries: [],
    quota: null,
    chatMessages: [],
    loading: false,
    error: null,
    ledgerTraces: [],
    ledgerTotalCount: 0,
    ledgerSummary: null,
    selectedTrace: null,
  });

  // Refs mirror the latest values so async callbacks read the current
  // sessionId / composition without participating in dep arrays — closes
  // stale-closure bugs where a fetch fires against a stale session.
  const sessionIdRef = useRef(state.sessionId);
  const compositionRef = useRef(state.composition);
  useEffect(() => {
    sessionIdRef.current = state.sessionId;
    compositionRef.current = state.composition;
  }, [state.sessionId, state.composition]);

  // One AbortController per logical fetch slot. Switching tabs or refiring
  // a query cancels the in-flight call so a stale response can't overwrite
  // newer state.
  const inflight = useRef<Record<string, AbortController | undefined>>({});
  const swapController = useCallback((key: string): AbortController => {
    inflight.current[key]?.abort();
    const ac = new AbortController();
    inflight.current[key] = ac;
    return ac;
  }, []);
  useEffect(() => {
    return () => {
      // Cancel everything on unmount.
      Object.values(inflight.current).forEach((ac) => ac?.abort());
    };
  }, []);

  const setMode = useCallback((mode: ConsoleMode) => {
    setState((s) => ({ ...s, mode }));
  }, []);

  const initSession = useCallback(async () => {
    setTenantId(tenantId);
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const sess = await createSession(tenantId, llmEnabled);
      setState((s) => ({ ...s, sessionId: sess.session_id, loading: false }));
    } catch (e: unknown) {
      console.error("[pi-console] initSession error:", e);
      setState((s) => ({ ...s, error: "Session initialization failed.", loading: false }));
    }
  }, [tenantId, llmEnabled]);

  const buildComposition = useCallback((nodes: CompositionNode[], edges: CompositionEdge[]) => {
    const req: ExplicitCompositionRequest = {
      request_id: `ecr_${Math.random().toString(36).slice(2, 10)}`,
      tenant_id: tenantId,
      console_session_id: state.sessionId,
      created_at: new Date().toISOString(),
      nodes,
      edges,
      global_policy_ref: "",
      global_schema_version: "1.0.0",
      global_bounds: { max_total_nodes: 64, max_depth: 8, max_fanout: 16, max_execution_time_ms: 300000 },
      simulation_only: true,
      approved_by_user: false,
      strict: true,
      request_hash: "",
    };
    setState((s) => ({ ...s, composition: req, simulationReport: null }));
  }, [tenantId, state.sessionId]);

  const runSimulation = useCallback(async () => {
    // Read through the ref so a rapid sequence of buildComposition →
    // runSimulation always simulates the latest DAG, not the closure-captured
    // snapshot from the render that created this callback.
    const composition = compositionRef.current;
    if (!composition) return;
    swapController("simulation");
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const res = await simulateComposition(composition);
      setState((s) => ({ ...s, simulationReport: { ...res.report, can_execute: res.can_execute }, loading: false }));
    } catch (e: unknown) {
      if ((e as { name?: string })?.name === "AbortError") return;
      console.error("[pi-console] runSimulation error:", e);
      setState((s) => ({ ...s, error: "Simulation failed. Please try again.", loading: false }));
    }
  }, [swapController]);

  const approveAndSubmit = useCallback(async () => {
    if (!state.composition || !state.simulationReport?.can_execute) return;
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const comp = { ...state.composition, approved_by_user: true, approval_timestamp: new Date().toISOString() };
      await submitComposition(comp, true);
      setState((s) => ({ ...s, composition: comp, loading: false }));
    } catch (e: unknown) {
      console.error("[pi-console] approveAndSubmit error:", e);
      setState((s) => ({ ...s, error: "Submission failed. Please try again.", loading: false }));
    }
  }, [state.composition, state.simulationReport]);

  const sendChat = useCallback(async (message: string) => {
    // Always use the live sessionId — capturing it in deps means a chat
    // sent during session init would post to "" and 400.
    const sessionId = sessionIdRef.current;
    swapController("chat");
    setState((s) => ({
      ...s,
      chatMessages: [...s.chatMessages, { role: "user", text: message }],
      loading: true,
      error: null,
    }));
    try {
      const res = await translateChat(sessionId, message);
      const assistantText = res.translation_valid
        ? `Translated to composition:\n${JSON.stringify(res.proposed_composition, null, 2)}\n\nExplanation: ${res.explanation}`
        : `Translation failed: ${res.validation_errors.join(", ")}`;
      setState((s) => ({
        ...s,
        chatMessages: [...s.chatMessages, { role: "assistant", text: assistantText }],
        loading: false,
        composition: res.proposed_composition || s.composition,
      }));
    } catch (e: unknown) {
      if ((e as { name?: string })?.name === "AbortError") return;
      const msg = e instanceof Error ? e.message : "Unknown error";
      console.error("[pi-console] chat error:", msg);
      setState((s) => ({
        ...s,
        chatMessages: [...s.chatMessages, { role: "assistant", text: "An error occurred. Please try again." }],
        loading: false,
        error: "Request failed. Please try again.",
      }));
    }
  }, [swapController]);

  const loadCapabilities = useCallback(async () => {
    setState((s) => ({ ...s, loading: true }));
    try {
      const res = await listCapabilities();
      const graph = await getCompatibilityGraph();
      setState((s) => ({
        ...s,
        capabilities: res.capabilities,
        compatNodes: graph.nodes,
        compatEdges: graph.edges,
        loading: false,
      }));
    } catch (e: unknown) {
      setState((s) => ({ ...s, error: "Request failed. Please try again.", loading: false }));
    }
  }, []);

  const loadAuditLog = useCallback(async () => {
    setState((s) => ({ ...s, loading: true }));
    try {
      const res = await getAuditLog();
      setState((s) => ({ ...s, auditEntries: res.entries, loading: false }));
    } catch (e: unknown) {
      setState((s) => ({ ...s, error: "Request failed. Please try again.", loading: false }));
    }
  }, []);

  const loadQuota = useCallback(async () => {
    try {
      const res = await getTenantQuota();
      setState((s) => ({ ...s, quota: res.quota }));
    } catch (e: unknown) {
      setState((s) => ({ ...s, error: "Request failed. Please try again." }));
    }
  }, []);

  const loadLedgerTraces = useCallback(async (
    limit = 50,
    offset = 0,
    nodeName?: string,
    success?: boolean,
    routedAgent?: string,
    search?: string,
    minRisk?: number
  ) => {
    // Cancel any prior in-flight ledger fetch so rapid filter changes
    // don't race responses out of order.
    const ac = swapController("ledger-traces");
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const res = await getLedgerTraces(limit, offset, nodeName, success, routedAgent, search, minRisk);
      if (ac.signal.aborted) return;
      setState((s) => ({ ...s, ledgerTraces: res.traces, ledgerTotalCount: res.total_count, loading: false }));
    } catch (e: unknown) {
      if ((e as { name?: string })?.name === "AbortError") return;
      setState((s) => ({ ...s, error: "Request failed. Please try again.", loading: false }));
    }
  }, [swapController]);

  const loadLedgerTraceDetail = useCallback(async (traceId: string) => {
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const res = await getLedgerTraceDetail(traceId);
      setState((s) => ({ ...s, selectedTrace: res, loading: false }));
    } catch (e: unknown) {
      setState((s) => ({ ...s, error: "Request failed. Please try again.", loading: false }));
    }
  }, []);

  const loadLedgerSummary = useCallback(async () => {
    try {
      const res = await getLedgerSummary();
      setState((s) => ({ ...s, ledgerSummary: res }));
    } catch (e: unknown) {
      setState((s) => ({ ...s, error: "Request failed. Please try again." }));
    }
  }, []);

  return {
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
    loadLedgerTraces,
    loadLedgerTraceDetail,
    loadLedgerSummary,
  };
}
