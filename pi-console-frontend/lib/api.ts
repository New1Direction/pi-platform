import {
  AuditLogEntry,
  CompatibilityEdge,
  CompatibilityNode,
  ExecutionReplayEvent,
  ExplicitCompositionRequest,
  MarketplaceCapability,
  SimulateCompositionResponse,
  TenantQuotaStatus,
} from "@/types";

const API_BASE = "/api/v1";

async function fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", "X-Tenant-ID": getTenantId() },
    ...init,
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`${res.status}: ${err}`);
  }
  return res.json() as Promise<T>;
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
  const res = await fetch(`${API_BASE}/sessions/create?tenant_id=${tenantId}&llm_enabled=${llmEnabled}`, {
    method: "POST",
    headers: { "X-Tenant-ID": tenantId },
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}
