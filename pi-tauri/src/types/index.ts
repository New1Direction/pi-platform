export interface CompositionNode {
  node_id: string;
  runtime: string;
  operation: string;
  artifacts: Record<string, unknown>[];
  required_schema_version: string;
  bounds: Record<string, number>;
  dependencies: string[];
}

export interface CompositionEdge {
  source: string;
  target: string;
  edge_type: "SEQUENTIAL" | "PARALLEL" | "CONDITIONAL" | "FAN_OUT" | "FAN_IN";
  condition?: string;
}

export interface ExplicitCompositionRequest {
  request_id: string;
  tenant_id: string;
  console_session_id: string;
  created_at: string;
  nodes: CompositionNode[];
  edges: CompositionEdge[];
  global_policy_ref: string;
  global_schema_version: string;
  global_bounds: Record<string, number>;
  simulation_only: boolean;
  approved_by_user: boolean;
  approval_timestamp?: string;
  strict: boolean;
  request_hash: string;
}

export interface SimulationReport {
  report_id: string;
  request_id: string;
  tenant_id: string;
  dag_valid: boolean;
  dag_errors: string[];
  bounds_respected: boolean;
  bounds_violations: string[];
  policy_violations: string[];
  estimated_blast_radius: Record<string, unknown>;
  execution_plan: string[];
  risk_level: "NONE" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  risk_details: string[];
  replay_safe: boolean;
  replay_verification_hash: string;
  report_hash: string;
  generated_at: string;
  can_execute?: boolean;
}

export interface SimulateCompositionResponse {
  report: SimulationReport;
  can_execute: boolean;
}

export interface MarketplaceCapability {
  capability_id: string;
  agent_name: string;
  runtime: string;
  operation: string;
  description: string;
  schema_version: string;
  trust_tier: "UNVERIFIED" | "VERIFIED" | "AUDITED" | "GOVERNED";
  compatibility_tags: string[];
  deterministic_bounds: Record<string, number>;
}

export interface CompatibilityNode {
  capability_id: string;
  runtime: string;
  trust_tier: string;
}

export interface CompatibilityEdge {
  source_capability: string;
  target_capability: string;
  compatible: boolean;
  reason: string;
}

export interface ExecutionReplayEvent {
  sequence_number: number;
  event_type: string;
  emitted_by: string;
  emitted_at: string;
  event_hash: string;
  previous_hash: string;
  payload_summary: Record<string, unknown>;
}

export interface AuditLogEntry {
  entry_id: string;
  timestamp: string;
  tenant_id: string;
  console_session_id: string;
  request_id: string;
  action: string;
  structured_request: Record<string, unknown>;
  response_status: string;
  user_ip: string;
}

export interface TenantQuotaStatus {
  tenant_id: string;
  compositions_submitted: number;
  compositions_executed: number;
  simulations_run: number;
  max_compositions_per_hour: number;
  max_simulations_per_hour: number;
  max_nodes_per_composition: number;
  current_hour_compositions: number;
  current_hour_simulations: number;
  quota_exceeded: boolean;
}

export interface TraceListItem {
  id: number;
  trace_id: string;
  node_name: string;
  input_payload_hash: string;
  llm_seed: number;
  llm_temperature: number;
  is_valid_type: boolean;
  timestamp: string;
  error_message?: string;
  success?: boolean;
  routed_agent?: string;
  risk_score?: number;
  output_summary?: string;
  anomalies_detected: string[];
}

export interface PaginatedTracesResponse {
  traces: TraceListItem[];
  total_count: number;
  limit: number;
  offset: number;
}

export interface TraceDetailResponse {
  id: number;
  trace_id: string;
  node_name: string;
  input_payload_hash: string;
  llm_seed: number;
  llm_temperature: number;
  is_valid_type: boolean;
  timestamp: string;
  error_message?: string;
  raw_output: string;
  parsed_output?: Record<string, any>;
}

export interface LedgerAnomaly {
  trace_id: string;
  node_name: string;
  timestamp: string;
  risk_score: number;
  error: string;
  summary: string;
}

// ── Agent Forge ──────────────────────────────────────────────────────────────

export interface ForgeGenerateRequest {
  description: string;
  keywords: string[];
  example_input?: string;
}

export interface ForgeGenerateResponse {
  code: string;
  agent_class_name: string;
  router_snippet: string;
  model_used: string;
}

export interface ForgeFinding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  message: string;
}

export interface ForgeAuditResponse {
  passed: boolean;
  findings: ForgeFinding[];
  structural_checks: Record<string, boolean>;
}

export interface ForgeSaveRequest {
  code: string;
  agent_name: string;
  description?: string;
}

export interface ForgeSaveResponse {
  saved_path: string;
  filename: string;
  trust_tier: string;
}

export interface ForgePendingAgent {
  filename: string;
  agent_name: string;
  class_name: string;
  method_name: string;
  keywords: string[];
  audit_passed: boolean;
  code: string;
}

export interface ForgePromoteResponse {
  agent_name: string;
  promoted_path: string;
  trust_tier: string;
  router_edit: string;
  consensus_edit: string;
  validated: boolean;
}

export interface LedgerSummaryResponse {
  total_traces: number;
  success_rate: number;
  avg_risk_score: number;
  anomalies_count: number;
  consensus_divergence_alerts: number;
  node_distribution: Record<string, number>;
  recent_anomalies: LedgerAnomaly[];
}
