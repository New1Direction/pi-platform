import {
  AuditLogEntry,
  CompatibilityEdge,
  CompatibilityNode,
  ExecutionReplayEvent,
  ExplicitCompositionRequest,
  MarketplaceCapability,
  SimulateCompositionResponse,
  TenantQuotaStatus,
  TraceListItem,
  PaginatedTracesResponse,
  TraceDetailResponse,
  LedgerSummaryResponse,
} from "@/types";

const API_BASE = "/api/v1";

const JWT_STORAGE_KEY = "pi.console.jwt";

export function setJwt(token: string) {
  if (typeof window !== "undefined") {
    window.localStorage.setItem(JWT_STORAGE_KEY, token);
  }
}

export function clearJwt() {
  if (typeof window !== "undefined") {
    window.localStorage.removeItem(JWT_STORAGE_KEY);
  }
}

export function getJwt(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(JWT_STORAGE_KEY);
}

function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Tenant-ID": getTenantId(),
  };
  const token = getJwt();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }
  return headers;
}

async function fetchJson<T>(
  path: string,
  init?: RequestInit,
  validate?: (data: unknown) => T,
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: authHeaders(),
    ...init,
  });
  if (!res.ok) {
    const err = await res.text();
    console.error(`[pi-api] ${res.status} ${path}:`, err);
    throw new Error(`Request failed (${res.status}). Please try again.`);
  }
  const data: unknown = await res.json();
  if (validate) {
    try {
      return validate(data);
    } catch (e) {
      console.error(`[pi-api] response shape validation failed for ${path}:`, e);
      throw new Error("Response from server was malformed. Please try again.");
    }
  }
  return data as T;
}

/**
 * Lightweight structural guard. Throws if `data` is not an object with the
 * listed keys present (value types are not checked, but null is rejected).
 * Use sparingly — TypeScript already covers compile-time shape; this is
 * just a runtime tripwire for backend drift.
 */
export function requireKeys<T>(data: unknown, keys: ReadonlyArray<keyof T & string>): T {
  if (data === null || typeof data !== "object") {
    throw new Error("expected object");
  }
  for (const k of keys) {
    if (!(k in (data as Record<string, unknown>))) {
      throw new Error(`missing key: ${k}`);
    }
  }
  return data as T;
}

let _tenantId = "default";
export function setTenantId(id: string) {
  _tenantId = id;
}
export function getTenantId() {
  return _tenantId;
}

export async function simulateComposition(
  composition: ExplicitCompositionRequest
): Promise<SimulateCompositionResponse> {
  return fetchJson<SimulateCompositionResponse>("/compositions/simulate", {
    method: "POST",
    body: JSON.stringify({ composition }),
  });
}

export async function submitComposition(
  composition: ExplicitCompositionRequest,
  userConfirmation: boolean
) {
  return fetchJson("/compositions/submit", {
    method: "POST",
    body: JSON.stringify({ composition, user_confirmation: userConfirmation }),
  });
}

export async function translateChat(
  consoleSessionId: string,
  message: string
): Promise<{ proposed_composition?: ExplicitCompositionRequest; translation_valid: boolean; validation_errors: string[]; explanation: string }> {
  return fetchJson("/compositions/translate-chat", {
    method: "POST",
    body: JSON.stringify({ console_session_id: consoleSessionId, tenant_id: _tenantId, user_message: message }),
  });
}

export async function listCapabilities(
  limit = 50,
  offset = 0,
  filterRuntime?: string
): Promise<{ capabilities: MarketplaceCapability[]; total: number }> {
  return fetchJson("/capabilities/list", {
    method: "POST",
    body: JSON.stringify({ tenant_id: _tenantId, limit, offset, filter_runtime: filterRuntime }),
  });
}

export async function getCompatibilityGraph(): Promise<{
  nodes: CompatibilityNode[];
  edges: CompatibilityEdge[];
}> {
  return fetchJson("/capabilities/compatibility-graph", {
    method: "POST",
    body: JSON.stringify({ tenant_id: _tenantId }),
  });
}

export async function getExecutionReplay(
  ledgerId: string,
  fromSequence?: number,
  toSequence?: number
): Promise<{ ledger_id: string; events: ExecutionReplayEvent[]; integrity_verified: boolean; total_events: number }> {
  return fetchJson("/replay/get", {
    method: "POST",
    body: JSON.stringify({ ledger_id: ledgerId, from_sequence: fromSequence, to_sequence: toSequence }),
  });
}

export async function getTenantQuota(): Promise<{ quota: TenantQuotaStatus }> {
  return fetchJson("/tenant/quota", {
    method: "POST",
    body: JSON.stringify({ tenant_id: _tenantId }),
  });
}

export async function getAuditLog(
  limit = 100,
  offset = 0,
  actionFilter?: string
): Promise<{ entries: AuditLogEntry[]; total: number }> {
  return fetchJson("/audit/log", {
    method: "POST",
    body: JSON.stringify({ tenant_id: _tenantId, limit, offset, action_filter: actionFilter }),
  });
}

export async function createSession(tenantId: string, llmEnabled = false): Promise<{ session_id: string; tenant_id: string }> {
  const params = new URLSearchParams({ tenant_id: tenantId, llm_enabled: String(llmEnabled) });
  const headers: Record<string, string> = { "X-Tenant-ID": tenantId };
  const token = getJwt();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`${API_BASE}/sessions/create?${params}`, {
    method: "POST",
    headers,
  });
  if (!res.ok) {
    const err = await res.text();
    console.error("[pi-api] createSession failed:", err);
    throw new Error(`Session creation failed (${res.status}). Please try again.`);
  }
  return res.json();
}

export async function getLedgerTraces(
  limit = 50,
  offset = 0,
  nodeName?: string,
  success?: boolean,
  routedAgent?: string,
  search?: string,
  minRisk?: number
): Promise<PaginatedTracesResponse> {
  const queryParams = new URLSearchParams();
  queryParams.append("limit", limit.toString());
  queryParams.append("offset", offset.toString());
  if (nodeName) queryParams.append("node_name", nodeName);
  if (success !== undefined) queryParams.append("success", success.toString());
  if (routedAgent) queryParams.append("routed_agent", routedAgent);
  if (search) queryParams.append("search", search);
  if (minRisk !== undefined) queryParams.append("min_risk", minRisk.toString());

  return fetchJson<PaginatedTracesResponse>(`/ledger/traces?${queryParams.toString()}`);
}

export async function getLedgerTraceDetail(traceId: string): Promise<TraceDetailResponse> {
  return fetchJson<TraceDetailResponse>(`/ledger/trace/${traceId}`);
}

export async function getLedgerSummary(): Promise<LedgerSummaryResponse> {
  return fetchJson<LedgerSummaryResponse>("/ledger/summary");
}
