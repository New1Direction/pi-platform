import type {
  AuditLogEntry,
  CompatibilityEdge,
  CompatibilityNode,
  ExecutionReplayEvent,
  ExplicitCompositionRequest,
  ForgeAuditResponse,
  ForgeGenerateRequest,
  ForgeGenerateResponse,
  ForgePendingAgent,
  ForgePromoteResponse,
  ForgeSaveRequest,
  ForgeSaveResponse,
  MarketplaceCapability,
  SimulateCompositionResponse,
  TenantQuotaStatus,
  PaginatedTracesResponse,
  TraceDetailResponse,
  LedgerSummaryResponse,
} from '../types';

const API_BASE = '/api/v1';
const JWT_KEY = 'pi.console.jwt';

let _tenantId = 'default';
export const setTenantId = (id: string) => { _tenantId = id; };
export const getTenantId = () => _tenantId;

export const setJwt = (t: string) => localStorage.setItem(JWT_KEY, t);
export const getJwt = () => localStorage.getItem(JWT_KEY);
export const clearJwt = () => localStorage.removeItem(JWT_KEY);

function headers(): HeadersInit {
  const h: Record<string, string> = { 'Content-Type': 'application/json', 'X-Tenant-ID': _tenantId };
  const jwt = getJwt();
  if (jwt) h['Authorization'] = `Bearer ${jwt}`;
  return h;
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { headers: headers(), ...init });
  if (!res.ok) throw new Error(`${res.status} ${path}`);
  return res.json() as Promise<T>;
}

export const createSession = (tenantId: string) => {
  const p = new URLSearchParams({ tenant_id: tenantId });
  return fetch(`${API_BASE}/sessions/create?${p}`, {
    method: 'POST', headers: { 'X-Tenant-ID': tenantId },
  }).then(r => r.json() as Promise<{ session_id: string; tenant_id: string }>);
};

export const listCapabilities = (limit = 100, offset = 0) =>
  api<{ capabilities: MarketplaceCapability[]; total: number }>('/capabilities/list', {
    method: 'POST', body: JSON.stringify({ tenant_id: _tenantId, limit, offset }),
  });

// Backend caps `limit` at 200; the registry has more agents than that, so page
// through to retrieve the full list. Bounded to avoid any runaway loop.
const CAP_PAGE = 200;
export const listAllCapabilities = async (): Promise<{ capabilities: MarketplaceCapability[]; total: number }> => {
  const first = await listCapabilities(CAP_PAGE, 0);
  let all = [...first.capabilities];
  const total = first.total;
  let offset = CAP_PAGE;
  let guard = 0;
  while (all.length < total && first.capabilities.length > 0 && guard < 50) {
    const page = await listCapabilities(CAP_PAGE, offset);
    if (page.capabilities.length === 0) break;
    all = all.concat(page.capabilities);
    offset += CAP_PAGE;
    guard += 1;
  }
  return { capabilities: all, total };
};

export const getCompatibilityGraph = () =>
  api<{ nodes: CompatibilityNode[]; edges: CompatibilityEdge[] }>('/capabilities/compatibility-graph', {
    method: 'POST', body: JSON.stringify({ tenant_id: _tenantId }),
  });

export const simulateComposition = (composition: ExplicitCompositionRequest) =>
  api<SimulateCompositionResponse>('/compositions/simulate', {
    method: 'POST', body: JSON.stringify({ composition }),
  });

export const submitComposition = (composition: ExplicitCompositionRequest) =>
  api('/compositions/submit', {
    method: 'POST', body: JSON.stringify({ composition, user_confirmation: true }),
  });

export const translateChat = (consoleSessionId: string, message: string) =>
  api<{ proposed_composition?: ExplicitCompositionRequest; translation_valid: boolean; explanation: string }>('/compositions/translate-chat', {
    method: 'POST', body: JSON.stringify({ console_session_id: consoleSessionId, tenant_id: _tenantId, user_message: message }),
  });

export const getExecutionReplay = (ledgerId: string) =>
  api<{ ledger_id: string; events: ExecutionReplayEvent[]; integrity_verified: boolean; total_events: number }>('/replay/get', {
    method: 'POST', body: JSON.stringify({ ledger_id: ledgerId }),
  });

export const getTenantQuota = () =>
  api<{ quota: TenantQuotaStatus }>('/tenant/quota', {
    method: 'POST', body: JSON.stringify({ tenant_id: _tenantId }),
  });

export const getAuditLog = (limit = 200, offset = 0) =>
  api<{ entries: AuditLogEntry[]; total: number }>('/audit/log', {
    method: 'POST', body: JSON.stringify({ tenant_id: _tenantId, limit, offset }),
  });

export const getLedgerTraces = (
  limit = 100, offset = 0, opts?: { node?: string; success?: boolean; search?: string; minRisk?: number }
) => {
  const q = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (opts?.node)             q.append('node_name', opts.node);
  if (opts?.success != null)  q.append('success', String(opts.success));
  if (opts?.search)           q.append('search', opts.search);
  if (opts?.minRisk != null)  q.append('min_risk', String(opts.minRisk));
  return api<PaginatedTracesResponse>(`/ledger/traces?${q}`);
};

export const getLedgerTraceDetail = (traceId: string) =>
  api<TraceDetailResponse>(`/ledger/trace/${traceId}`);

export const getLedgerSummary = () =>
  api<LedgerSummaryResponse>('/ledger/summary');

const LS_FORGE_KEY = 'pi_ai_apikey';
export const getForgeApiKey = () => localStorage.getItem(LS_FORGE_KEY) ?? '';
export const setForgeApiKey = (k: string) => localStorage.setItem(LS_FORGE_KEY, k);

function forgeHeaders(apiKey: string): HeadersInit {
  return {
    'Content-Type': 'application/json',
    'X-Tenant-ID': _tenantId,
    'x-anthropic-key': apiKey,
  };
}

export const forgeGenerate = (req: ForgeGenerateRequest, apiKey: string) =>
  fetch(`${API_BASE}/forge/generate`, {
    method: 'POST',
    headers: forgeHeaders(apiKey),
    body: JSON.stringify(req),
  }).then(async r => {
    if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error((d as any).detail ?? `${r.status}`); }
    return r.json() as Promise<ForgeGenerateResponse>;
  });

export const forgeAudit = (code: string, agentName = '') =>
  api<ForgeAuditResponse>('/forge/audit', {
    method: 'POST', body: JSON.stringify({ code, agent_name: agentName }),
  });

export const forgeSave = (req: ForgeSaveRequest, apiKey: string) =>
  fetch(`${API_BASE}/forge/save`, {
    method: 'POST',
    headers: forgeHeaders(apiKey),
    body: JSON.stringify(req),
  }).then(async r => {
    if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error((d as any).detail ?? `${r.status}`); }
    return r.json() as Promise<ForgeSaveResponse>;
  });

export const forgeListPending = () =>
  api<{ agents: ForgePendingAgent[] }>('/forge/pending');

export const forgePromote = (filename: string) =>
  fetch(`${API_BASE}/forge/promote`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Tenant-ID': _tenantId },
    body: JSON.stringify({ filename }),
  }).then(async r => {
    if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error((d as any).detail ?? `${r.status}`); }
    return r.json() as Promise<ForgePromoteResponse>;
  });
