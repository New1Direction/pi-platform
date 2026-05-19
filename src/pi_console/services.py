"""PI Console Core Proxy Service.

Thin, stateless validation and forwarding layer.
- Receives ExplicitCompositionRequest
- Validates schema strictly
- Logs every interaction immutably
- Forwards to PI Core via deterministic adapter
- Returns structured responses

NO direct database access.
NO direct worker access.
NO LLM inference in this module.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pi_console.schemas import (
    AuditLogEntry,
    ConsoleSession,
    ExecutionReplayEvent,
    ExplicitCompositionRequest,
    GetAuditLogRequest,
    GetAuditLogResponse,
    GetCompatibilityGraphRequest,
    GetCompatibilityGraphResponse,
    GetExecutionReplayRequest,
    GetExecutionReplayResponse,
    GetTenantQuotaStatusRequest,
    GetTenantQuotaStatusResponse,
    ListMarketplaceCapabilitiesRequest,
    ListMarketplaceCapabilitiesResponse,
    MarketplaceCapability,
    SimulateCompositionRequest,
    SimulateCompositionResponse,
    SimulationReport,
    SubmitCompositionRequest,
    SubmitCompositionResponse,
    TenantQuotaStatus,
    CompatibilityNode,
    CompatibilityEdge,
)


class ConsoleAuditStore:
    """Append-only audit store for console interactions.

    Stores to local JSONL for replayability.
    In production: forward to immutable log sink (e.g. S3, append-only DB).
    """

    def __init__(self, log_dir: Path) -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

    def _path(self, tenant_id: str) -> Path:
        return self.log_dir / f"audit_{tenant_id}.jsonl"

    def append(self, entry: AuditLogEntry) -> None:
        path = self._path(entry.tenant_id)
        with open(path, "a") as f:
            f.write(json.dumps(entry.model_dump(), default=str) + "\n")

    def query(
        self,
        tenant_id: str,
        console_session_id: Optional[str] = None,
        action_filter: Optional[str] = None,
        from_timestamp: Optional[datetime] = None,
        to_timestamp: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditLogEntry]:
        path = self._path(tenant_id)
        if not path.exists():
            return []
        results: List[AuditLogEntry] = []
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                if console_session_id and data.get("console_session_id") != console_session_id:
                    continue
                if action_filter and data.get("action") != action_filter:
                    continue
                ts = data.get("timestamp")
                if from_timestamp and ts and datetime.fromisoformat(ts) < from_timestamp:
                    continue
                if to_timestamp and ts and datetime.fromisoformat(ts) > to_timestamp:
                    continue
                results.append(AuditLogEntry(**data))
        # Sort by timestamp descending
        results.sort(key=lambda e: e.timestamp, reverse=True)
        return results[offset : offset + limit]

    def count(
        self,
        tenant_id: str,
        console_session_id: Optional[str] = None,
        action_filter: Optional[str] = None,
        from_timestamp: Optional[datetime] = None,
        to_timestamp: Optional[datetime] = None,
    ) -> int:
        return len(self.query(tenant_id, console_session_id, action_filter, from_timestamp, to_timestamp, limit=10_000, offset=0))


class ConsoleSessionStore:
    """In-memory session store (ephemeral). Sessions expire after inactivity."""

    def __init__(self, max_sessions: int = 1024) -> None:
        self._sessions: Dict[str, ConsoleSession] = {}
        self._max_sessions = max_sessions

    def create(self, tenant_id: str, llm_enabled: bool = False, llm_provider: Optional[str] = None) -> ConsoleSession:
        if len(self._sessions) >= self._max_sessions:
            # Evict oldest by last_activity_at
            oldest = min(self._sessions.values(), key=lambda s: s.last_activity_at)
            del self._sessions[oldest.session_id]
        session = ConsoleSession(
            tenant_id=tenant_id,
            llm_enabled=llm_enabled,
            llm_provider=llm_provider,
        )
        self._sessions[session.session_id] = session
        return session

    def get(self, session_id: str) -> Optional[ConsoleSession]:
        session = self._sessions.get(session_id)
        if session:
            session.last_activity_at = datetime.now(timezone.utc)
        return session

    def list_active(self) -> List[ConsoleSession]:
        return list(self._sessions.values())

    def mark_approved(self, session_id: str, request_id: str) -> None:
        session = self._sessions.get(session_id)
        if session:
            if request_id not in session.approved_request_ids:
                session.approved_request_ids.append(request_id)

    def mark_rejected(self, session_id: str, request_id: str) -> None:
        session = self._sessions.get(session_id)
        if session:
            if request_id not in session.rejected_request_ids:
                session.rejected_request_ids.append(request_id)


class QuotaTracker:
    """In-memory quota tracker per tenant (ephemeral; production uses persistent store)."""

    def __init__(self) -> None:
        self._quotas: Dict[str, TenantQuotaStatus] = {}

    def get(self, tenant_id: str) -> TenantQuotaStatus:
        return self._quotas.get(tenant_id) or TenantQuotaStatus(tenant_id=tenant_id)

    def record_composition(self, tenant_id: str) -> TenantQuotaStatus:
        q = self._quotas.get(tenant_id) or TenantQuotaStatus(tenant_id=tenant_id)
        q.compositions_submitted += 1
        q.current_hour_compositions += 1
        q.quota_exceeded = q.current_hour_compositions > q.max_compositions_per_hour
        self._quotas[tenant_id] = q
        return q

    def record_simulation(self, tenant_id: str) -> TenantQuotaStatus:
        q = self._quotas.get(tenant_id) or TenantQuotaStatus(tenant_id=tenant_id)
        q.simulations_run += 1
        q.current_hour_simulations += 1
        self._quotas[tenant_id] = q
        return q

    def record_execution(self, tenant_id: str) -> TenantQuotaStatus:
        q = self._quotas.get(tenant_id) or TenantQuotaStatus(tenant_id=tenant_id)
        q.compositions_executed += 1
        self._quotas[tenant_id] = q
        return q


class CoreAdapter:
    """Deterministic adapter to PI Core.

    This adapter knows how to map ExplicitCompositionRequest to core runtime calls.
    In this reference implementation, it simulates core responses for independence.
    In production, this calls the core API (gRPC/HTTP) with strict timeouts.
    """

    def __init__(self, core_endpoint: str = "http://localhost:9000") -> None:
        self.core_endpoint = core_endpoint

    def simulate(self, request: ExplicitCompositionRequest) -> SimulateCompositionResponse:
        """Run deterministic simulation against the composition DAG."""
        start = time.time()
        report = SimulationReport(request_id=request.request_id, tenant_id=request.tenant_id)

        # 1. DAG validation
        node_ids = {n.node_id for n in request.nodes}
        dag_errors: List[str] = []
        for edge in request.edges:
            if edge.source not in node_ids:
                dag_errors.append(f"Edge references unknown source: {edge.source}")
            if edge.target not in node_ids:
                dag_errors.append(f"Edge references unknown target: {edge.target}")

        # 2. Cycle detection (simple DFS)
        adj: Dict[str, List[str]] = {n.node_id: [] for n in request.nodes}
        for e in request.edges:
            adj[e.source].append(e.target)
        visited: set = set()
        rec_stack: set = set()
        def _has_cycle(v: str) -> bool:
            visited.add(v)
            rec_stack.add(v)
            for neighbor in adj.get(v, []):
                if neighbor not in visited:
                    if _has_cycle(neighbor):
                        return True
                elif neighbor in rec_stack:
                    return True
            rec_stack.remove(v)
            return False
        for node in request.nodes:
            if node.node_id not in visited:
                if _has_cycle(node.node_id):
                    dag_errors.append("Cycle detected in composition DAG")
                    break

        # 3. Bounds validation
        bounds_violations: List[str] = []
        total_nodes = len(request.nodes)
        gb = request.global_bounds
        if total_nodes > gb.get("max_total_nodes", 64):
            bounds_violations.append(f"Node count {total_nodes} exceeds max {gb.get('max_total_nodes')}")
        max_depth = 0
        for node in request.nodes:
            depth = 0
            current = node.node_id
            seen: set = set()
            while current in adj and adj[current]:
                if current in seen:
                    break
                seen.add(current)
                current = adj[current][0]
                depth += 1
            max_depth = max(max_depth, depth)
        if max_depth > gb.get("max_depth", 8):
            bounds_violations.append(f"Depth {max_depth} exceeds max {gb.get('max_depth')}")

        # 4. Build execution plan (topological-ish order)
        execution_plan = [n.node_id for n in request.nodes]

        # 5. Risk assessment (deterministic)
        risk_level: str = "NONE"
        risk_details: List[str] = []
        if dag_errors:
            risk_level = "CRITICAL"
            risk_details.append("DAG structural errors block execution")
        elif bounds_violations:
            risk_level = "HIGH"
            risk_details.append("Global bounds exceeded")
        elif total_nodes > 32:
            risk_level = "MEDIUM"
            risk_details.append("Large composition: review carefully")

        report = SimulationReport(
            request_id=request.request_id,
            tenant_id=request.tenant_id,
            dag_valid=len(dag_errors) == 0,
            dag_errors=dag_errors,
            bounds_respected=len(bounds_violations) == 0,
            bounds_violations=bounds_violations,
            execution_plan=execution_plan,
            risk_level=risk_level,  # type: ignore[arg-type]
            risk_details=risk_details,
            replay_safe=len(dag_errors) == 0 and len(bounds_violations) == 0,
            report_hash="",
        )
        report = report.model_copy(update={"report_hash": report.compute_hash()})

        can_execute = report.dag_valid and report.bounds_respected and len(report.policy_violations) == 0
        return SimulateCompositionResponse(report=report, can_execute=can_execute)

    def submit(self, request: ExplicitCompositionRequest) -> SubmitCompositionResponse:
        """Forward approved composition to PI Core."""
        # In production: POST to core with strict timeout, parse deterministic response
        # Here: simulate deterministic acceptance
        return SubmitCompositionResponse(
            request_id=request.request_id,
            accepted=True,
            status="QUEUED",
            message="Composition queued for deterministic execution",
            core_ledger_id=f"ledger_{request.request_id}",
            estimated_execution_time_ms=request.global_bounds.get("max_execution_time_ms", 300_000),
        )

    def get_execution_replay(self, ledger_id: str, from_seq: Optional[int] = None, to_seq: Optional[int] = None) -> GetExecutionReplayResponse:
        """Fetch replay events from core."""
        # Simulated: in production, query core replay ledger API
        events = [
            ExecutionReplayEvent(
                sequence_number=i,
                event_type="ARTIFACT_RECEIVED",
                emitted_by="pi-interoperability-layer",
                emitted_at=datetime.now(timezone.utc).isoformat(),
                event_hash=f"evhash_{i:04d}",
                previous_hash=f"evhash_{i-1:04d}" if i > 1 else "",
                payload_summary={"node_id": f"node_{i}", "status": "completed"},
            )
            for i in range(1, 6)
        ]
        if from_seq is not None:
            events = [e for e in events if e.sequence_number >= from_seq]
        if to_seq is not None:
            events = [e for e in events if e.sequence_number <= to_seq]
        return GetExecutionReplayResponse(
            ledger_id=ledger_id,
            events=events,
            integrity_verified=True,
            total_events=len(events),
        )

    def list_capabilities(self, tenant_id: str, runtime_filter: Optional[str] = None, operation_filter: Optional[str] = None, limit: int = 50, offset: int = 0) -> ListMarketplaceCapabilitiesResponse:
        """Query capability marketplace registry."""
        # Simulated static registry; production queries the real CapabilityMarketplaceRegistry
        all_caps = [
            MarketplaceCapability(
                capability_id="cap_recon_validate",
                runtime="pi-semantic-recon",
                operation="VALIDATE",
                description="Semantic reconnaissance validation pass",
                schema_version="1.0.0",
                trust_tier="GOVERNED",
                deterministic_bounds={"max_depth": 8, "max_fanout": 16},
            ),
            MarketplaceCapability(
                capability_id="cap_diff_blast",
                runtime="pi-semantic-diff",
                operation="BLAST_RADIUS",
                description="Diff-based blast radius computation",
                schema_version="1.0.0",
                trust_tier="AUDITED",
                deterministic_bounds={"max_depth": 6, "max_fanout": 12},
            ),
            MarketplaceCapability(
                capability_id="cap_validator_audit",
                runtime="pi-semantic-validator",
                operation="AUDIT",
                description="Validation report audit trail",
                schema_version="1.0.0",
                trust_tier="GOVERNED",
                deterministic_bounds={"max_depth": 4, "max_fanout": 8},
            ),
            MarketplaceCapability(
                capability_id="cap_governor_sandbox",
                runtime="pi-extension-governor",
                operation="SANDBOX",
                description="Sandboxed capability execution",
                schema_version="1.0.0",
                trust_tier="GOVERNED",
                deterministic_bounds={"max_depth": 2, "max_fanout": 4},
            ),
            MarketplaceCapability(
                capability_id="cap_catalog_ingest",
                runtime="pi-catalog-integration",
                operation="INGEST",
                description="Catalog package ingestion pipeline",
                schema_version="1.0.0",
                trust_tier="VERIFIED",
                deterministic_bounds={"max_depth": 4, "max_fanout": 8},
            ),
        ]
        if runtime_filter:
            all_caps = [c for c in all_caps if c.runtime == runtime_filter]
        if operation_filter:
            all_caps = [c for c in all_caps if c.operation == operation_filter]
        total = len(all_caps)
        return ListMarketplaceCapabilitiesResponse(
            capabilities=all_caps[offset : offset + limit],
            total=total,
            limit=limit,
            offset=offset,
        )

    def get_compatibility_graph(self, tenant_id: str, runtime_filter: Optional[str] = None) -> GetCompatibilityGraphResponse:
        """Return compatibility graph for visual builder."""
        # Static demo graph; production queries real graph
        nodes = [
            CompatibilityNode(capability_id="cap_recon_validate", runtime="pi-semantic-recon", trust_tier="GOVERNED"),
            CompatibilityNode(capability_id="cap_diff_blast", runtime="pi-semantic-diff", trust_tier="AUDITED"),
            CompatibilityNode(capability_id="cap_validator_audit", runtime="pi-semantic-validator", trust_tier="GOVERNED"),
            CompatibilityNode(capability_id="cap_governor_sandbox", runtime="pi-extension-governor", trust_tier="GOVERNED"),
        ]
        edges = [
            CompatibilityEdge(source_capability="cap_recon_validate", target_capability="cap_diff_blast", compatible=True, reason="same schema major version"),
            CompatibilityEdge(source_capability="cap_diff_blast", target_capability="cap_validator_audit", compatible=True, reason="backward compatible"),
            CompatibilityEdge(source_capability="cap_validator_audit", target_capability="cap_governor_sandbox", compatible=False, reason="trust tier gap"),
        ]
        if runtime_filter:
            nodes = [n for n in nodes if n.runtime == runtime_filter]
            node_ids = {n.capability_id for n in nodes}
            edges = [e for e in edges if e.source_capability in node_ids and e.target_capability in node_ids]
        return GetCompatibilityGraphResponse(nodes=nodes, edges=edges)
