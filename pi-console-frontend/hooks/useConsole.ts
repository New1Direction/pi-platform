"use client";

import { useState, useCallback } from "react";
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
  });

  const setMode = useCallback((mode: ConsoleMode) => {
    setState((s) => ({ ...s, mode }));
  }, []);

  const initSession = useCallback(async () => {
    setTenantId(tenantId);
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const sess = await createSession(tenantId, llmEnabled);
      setState((s) => ({ ...s, sessionId: sess.session_id, loading: false }));
    } catch (e: any) {
      setState((s) => ({ ...s, error: e.message, loading: false }));
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
    if (!state.composition) return;
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const res = await simulateComposition(state.composition);
      setState((s) => ({ ...s, simulationReport: res.report, loading: false }));
    } catch (e: any) {
      setState((s) => ({ ...s, error: e.message, loading: false }));
    }
  }, [state.composition]);

  const approveAndSubmit = useCallback(async () => {
    if (!state.composition || !state.simulationReport?.can_execute) return;
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const comp = { ...state.composition, approved_by_user: true, approval_timestamp: new Date().toISOString() };
      await submitComposition(comp, true);
      setState((s) => ({ ...s, composition: comp, loading: false }));
    } catch (e: any) {
      setState((s) => ({ ...s, error: e.message, loading: false }));
    }
  }, [state.composition, state.simulationReport]);

  const sendChat = useCallback(async (message: string) => {
    setState((s) => ({
      ...s,
      chatMessages: [...s.chatMessages, { role: "user", text: message }],
      loading: true,
      error: null,
    }));
    try {
      const res = await translateChat(state.sessionId, message);
      const assistantText = res.translation_valid
        ? `Translated to composition:\n${JSON.stringify(res.proposed_composition, null, 2)}\n\nExplanation: ${res.explanation}`
        : `Translation failed: ${res.validation_errors.join(", ")}`;
      setState((s) => ({
        ...s,
        chatMessages: [...s.chatMessages, { role: "assistant", text: assistantText }],
        loading: false,
        composition: res.proposed_composition || s.composition,
      }));
    } catch (e: any) {
      setState((s) => ({
        ...s,
        chatMessages: [...s.chatMessages, { role: "assistant", text: `Error: ${e.message}` }],
        loading: false,
        error: e.message,
      }));
    }
  }, [state.sessionId]);

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
    } catch (e: any) {
      setState((s) => ({ ...s, error: e.message, loading: false }));
    }
  }, []);

  const loadAuditLog = useCallback(async () => {
    setState((s) => ({ ...s, loading: true }));
    try {
      const res = await getAuditLog();
      setState((s) => ({ ...s, auditEntries: res.entries, loading: false }));
    } catch (e: any) {
      setState((s) => ({ ...s, error: e.message, loading: false }));
    }
  }, []);

  const loadQuota = useCallback(async () => {
    try {
      const res = await getTenantQuota();
      setState((s) => ({ ...s, quota: res.quota }));
    } catch (e: any) {
      setState((s) => ({ ...s, error: e.message }));
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
  };
}
