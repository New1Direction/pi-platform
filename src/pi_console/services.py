"""PI Console Core Proxy Service.

Thin validation + forwarding layer between the FastAPI console and the
real PI execution surfaces:

- ``simulate()``  → in-process DAG validation (cycle/bounds/risk)
- ``submit()``    → ``PiOrchestrator.execute_goal()`` per node, writing
                    ``ExecutionTrace`` rows into a shared ``StateLedger``
- ``get_execution_replay()`` → ``StateLedger.get_trace(ledger_id)``
- ``list_capabilities()``    → ``AgentRouter.routes`` registry
- ``get_compatibility_graph()`` → static demo graph (still simulated)

NO LLM inference in this module — natural language is the orchestrator's
job, and we only forward strict, validated envelopes.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_services_logger = logging.getLogger("pi_console.services")


_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _safe_tenant_id(tenant_id: str) -> str:
    """Reject any tenant_id that could traverse out of the audit log directory."""
    if not isinstance(tenant_id, str) or not _TENANT_ID_RE.match(tenant_id):
        raise ValueError(f"invalid tenant_id: must match [A-Za-z0-9_-]{{1,64}} (got {tenant_id!r})")
    return tenant_id


from pi_console.schemas import (
    AuditLogEntry,
    CompatibilityEdge,
    CompatibilityNode,
    ConsoleSession,
    ExecutionReplayEvent,
    ExplicitCompositionRequest,
    GetCompatibilityGraphResponse,
    GetExecutionReplayResponse,
    ListMarketplaceCapabilitiesResponse,
    MarketplaceCapability,
    SimulateCompositionResponse,
    SimulationReport,
    SubmitCompositionResponse,
    TenantQuotaStatus,
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
        return self.log_dir / f"audit_{_safe_tenant_id(tenant_id)}.jsonl"

    def append(self, entry: AuditLogEntry) -> None:
        path = self._path(entry.tenant_id)
        with open(path, "a") as f:
            f.write(json.dumps(entry.model_dump(), default=str) + "\n")

    def _iter_matching(
        self,
        tenant_id: str,
        console_session_id: Optional[str],
        action_filter: Optional[str],
        from_timestamp: Optional[datetime],
        to_timestamp: Optional[datetime],
    ):
        """
        Yield matching audit dicts newest-first. The on-disk JSONL is
        append-only and therefore already in chronological order, so we read
        the file in reverse to avoid materialising the whole log before
        sorting+slicing.
        """
        path = self._path(tenant_id)
        if not path.exists():
            return

        with open(path, "rb") as f:
            f.seek(0, 2)
            file_size = f.tell()
            if file_size == 0:
                return

            chunk_size = 64 * 1024
            buffer = b""
            position = file_size
            tail: List[bytes] = []

            while position > 0:
                read_size = min(chunk_size, position)
                position -= read_size
                f.seek(position)
                buffer = f.read(read_size) + buffer
                lines = buffer.split(b"\n")
                # First chunk after the last newline may be partial — hold it
                # until we read further back, unless we're at BOF.
                buffer = lines[0] if position > 0 else b""
                tail.extend(reversed(lines[1:] if position > 0 else lines))

                while tail:
                    raw = tail.pop(0).strip()
                    if not raw:
                        continue
                    try:
                        data = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    if console_session_id and data.get("console_session_id") != console_session_id:
                        continue
                    if action_filter and data.get("action") != action_filter:
                        continue
                    ts = data.get("timestamp")
                    if ts and (from_timestamp or to_timestamp):
                        try:
                            ts_parsed = datetime.fromisoformat(ts)
                        except ValueError:
                            ts_parsed = None
                        if ts_parsed:
                            if from_timestamp and ts_parsed < from_timestamp:
                                continue
                            if to_timestamp and ts_parsed > to_timestamp:
                                continue
                    yield data

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
        results: List[AuditLogEntry] = []
        skipped = 0
        for data in self._iter_matching(tenant_id, console_session_id, action_filter, from_timestamp, to_timestamp):
            if skipped < offset:
                skipped += 1
                continue
            results.append(AuditLogEntry(**data))
            if len(results) >= limit:
                break
        return results

    def count(
        self,
        tenant_id: str,
        console_session_id: Optional[str] = None,
        action_filter: Optional[str] = None,
        from_timestamp: Optional[datetime] = None,
        to_timestamp: Optional[datetime] = None,
    ) -> int:
        return sum(
            1 for _ in self._iter_matching(tenant_id, console_session_id, action_filter, from_timestamp, to_timestamp)
        )


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
    """Per-tenant quota tracker.

    Backed by SQLite when ``PI_QUOTA_DB_PATH`` is set (or passed explicitly),
    so counts survive process restart. Without a path, falls back to an
    in-memory dict — useful for tests and the smoke driver.
    """

    _COLUMNS = (
        "compositions_submitted",
        "compositions_executed",
        "simulations_run",
        "max_compositions_per_hour",
        "max_simulations_per_hour",
        "max_nodes_per_composition",
        "current_hour_compositions",
        "current_hour_simulations",
        "quota_exceeded",
    )

    WINDOW_SECONDS = 3600  # rolling hour for current_hour_* counters

    def __init__(self, db_path: Optional[str] = None) -> None:
        resolved = db_path or os.getenv("PI_QUOTA_DB_PATH")
        self._db_path: Optional[str] = resolved or None
        self._quotas: Dict[str, TenantQuotaStatus] = {}
        # In-memory window-start timestamps (when db_path is None) and
        # mirrors of the SQLite column for fast in-process resets.
        self._window_started_at: Dict[str, float] = {}
        if self._db_path:
            self._ensure_schema()

    def _conn(self):
        import sqlite3

        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _ensure_schema(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tenant_quota (
                    tenant_id TEXT PRIMARY KEY,
                    compositions_submitted INTEGER NOT NULL DEFAULT 0,
                    compositions_executed INTEGER NOT NULL DEFAULT 0,
                    simulations_run INTEGER NOT NULL DEFAULT 0,
                    max_compositions_per_hour INTEGER NOT NULL DEFAULT 100,
                    max_simulations_per_hour INTEGER NOT NULL DEFAULT 500,
                    max_nodes_per_composition INTEGER NOT NULL DEFAULT 64,
                    current_hour_compositions INTEGER NOT NULL DEFAULT 0,
                    current_hour_simulations INTEGER NOT NULL DEFAULT 0,
                    quota_exceeded INTEGER NOT NULL DEFAULT 0,
                    window_started_at REAL NOT NULL DEFAULT 0
                )
                """
            )
            # Forward-migrate existing rows that pre-date the column.
            cols = {row[1] for row in conn.execute("PRAGMA table_info(tenant_quota)").fetchall()}
            if "window_started_at" not in cols:
                conn.execute("ALTER TABLE tenant_quota ADD COLUMN window_started_at REAL NOT NULL DEFAULT 0")

    def _maybe_reset_window(self, q: TenantQuotaStatus, window_started_at: float) -> tuple[TenantQuotaStatus, float]:
        """Roll over the current-hour counters if the window has elapsed.

        Returns the (possibly mutated) quota and the (possibly fresh)
        window-start timestamp the caller should persist.
        """
        now = time.time()
        if window_started_at == 0 or (now - window_started_at) > self.WINDOW_SECONDS:
            q.current_hour_compositions = 0
            q.current_hour_simulations = 0
            q.quota_exceeded = False
            window_started_at = now
        return q, window_started_at

    def _load(self, tenant_id: str) -> tuple[TenantQuotaStatus, float]:
        if not self._db_path:
            q = self._quotas.get(tenant_id) or TenantQuotaStatus(tenant_id=tenant_id)
            window = self._window_started_at.get(tenant_id, 0.0)
            return q, window
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM tenant_quota WHERE tenant_id = ?",
                (_safe_tenant_id(tenant_id),),
            ).fetchone()
        if row is None:
            return TenantQuotaStatus(tenant_id=tenant_id), 0.0
        q = TenantQuotaStatus(
            tenant_id=tenant_id,
            compositions_submitted=row["compositions_submitted"],
            compositions_executed=row["compositions_executed"],
            simulations_run=row["simulations_run"],
            max_compositions_per_hour=row["max_compositions_per_hour"],
            max_simulations_per_hour=row["max_simulations_per_hour"],
            max_nodes_per_composition=row["max_nodes_per_composition"],
            current_hour_compositions=row["current_hour_compositions"],
            current_hour_simulations=row["current_hour_simulations"],
            quota_exceeded=bool(row["quota_exceeded"]),
        )
        return q, float(row["window_started_at"])

    def _save(self, q: TenantQuotaStatus, window_started_at: float) -> None:
        if not self._db_path:
            self._quotas[q.tenant_id] = q
            self._window_started_at[q.tenant_id] = window_started_at
            return
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO tenant_quota (
                    tenant_id, compositions_submitted, compositions_executed,
                    simulations_run, max_compositions_per_hour,
                    max_simulations_per_hour, max_nodes_per_composition,
                    current_hour_compositions, current_hour_simulations,
                    quota_exceeded, window_started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    compositions_submitted = excluded.compositions_submitted,
                    compositions_executed = excluded.compositions_executed,
                    simulations_run = excluded.simulations_run,
                    max_compositions_per_hour = excluded.max_compositions_per_hour,
                    max_simulations_per_hour = excluded.max_simulations_per_hour,
                    max_nodes_per_composition = excluded.max_nodes_per_composition,
                    current_hour_compositions = excluded.current_hour_compositions,
                    current_hour_simulations = excluded.current_hour_simulations,
                    quota_exceeded = excluded.quota_exceeded,
                    window_started_at = excluded.window_started_at
                """,
                (
                    _safe_tenant_id(q.tenant_id),
                    q.compositions_submitted,
                    q.compositions_executed,
                    q.simulations_run,
                    q.max_compositions_per_hour,
                    q.max_simulations_per_hour,
                    q.max_nodes_per_composition,
                    q.current_hour_compositions,
                    q.current_hour_simulations,
                    int(q.quota_exceeded),
                    window_started_at,
                ),
            )
            conn.commit()

    def get(self, tenant_id: str) -> TenantQuotaStatus:
        q, window = self._load(tenant_id)
        q, window = self._maybe_reset_window(q, window)
        # Persist the reset so subsequent reads see the cleared counters.
        self._save(q, window)
        return q

    def record_composition(self, tenant_id: str) -> TenantQuotaStatus:
        q, window = self._load(tenant_id)
        q, window = self._maybe_reset_window(q, window)
        q.compositions_submitted += 1
        q.current_hour_compositions += 1
        q.quota_exceeded = q.current_hour_compositions > q.max_compositions_per_hour
        self._save(q, window)
        return q

    def record_simulation(self, tenant_id: str) -> TenantQuotaStatus:
        q, window = self._load(tenant_id)
        q, window = self._maybe_reset_window(q, window)
        q.simulations_run += 1
        q.current_hour_simulations += 1
        self._save(q, window)
        return q

    def record_execution(self, tenant_id: str) -> TenantQuotaStatus:
        q, window = self._load(tenant_id)
        q, window = self._maybe_reset_window(q, window)
        q.compositions_executed += 1
        self._save(q, window)
        return q


class CoreAdapter:
    """Deterministic adapter to PI Core.

    Wires the console boundary to the real execution surfaces:

      * ``PiOrchestrator.execute_goal()`` for submit
      * ``StateLedger`` for replay queries
      * ``AgentRouter.routes`` for capability listing

    The constructor accepts a ``StateLedger`` (shared instance for
    cross-request continuity) and an optional ``PiOrchestrator``. If you
    don't pass either, an in-memory pair is created — fine for tests,
    not durable for prod.
    """

    def __init__(
        self,
        core_endpoint: str = "http://localhost:9000",
        ledger: Optional[Any] = None,
        orchestrator: Optional[Any] = None,
    ) -> None:
        self.core_endpoint = core_endpoint
        # Lazy import so the console boundary stays importable even if the
        # micro-agent stack has unrelated import issues.
        try:
            from pi_agent_chain.ledger import StateLedger
            from pi_micro_agents.orchestrator.core import PiOrchestrator

            ledger_path = os.getenv("PI_STATE_LEDGER_PATH", ":memory:")
            self._ledger = ledger if ledger is not None else StateLedger(ledger_path)
            self._orchestrator = orchestrator if orchestrator is not None else PiOrchestrator(ledger=self._ledger)
        except Exception as e:  # pragma: no cover — fail-soft for partial installs
            _services_logger.warning("PI Core surfaces unavailable, falling back to in-memory stubs: %s", e)
            self._ledger = None
            self._orchestrator = None

    def simulate(self, request: ExplicitCompositionRequest) -> SimulateCompositionResponse:
        """Run deterministic simulation against the composition DAG."""
        time.time()
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
        # Content-address the report_id BEFORE hashing. SimulationReport.report_id
        # defaults to f"sim_{uuid.uuid4().hex[:16]}" and SimulationReport.compute_hash
        # folds report_id into the hashed payload — so a random report_id makes the
        # advertised "deterministic report_hash" change every run. Derive report_id
        # deterministically from the logical report content (everything except the
        # random/wall-clock fields report_id/report_hash/generated_at) so the same
        # logical simulation reproduces the same report_id, and therefore the same
        # report_hash, across runs. The field is preserved — it is still a unique
        # per-content identifier — just no longer salted by uuid4.
        content_payload = report.model_dump(exclude={"report_id", "report_hash", "generated_at"})
        content_canonical = json.dumps(content_payload, sort_keys=True, separators=(",", ":"), default=str)
        deterministic_report_id = f"sim_{hashlib.sha256(content_canonical.encode()).hexdigest()[:16]}"
        report = report.model_copy(update={"report_id": deterministic_report_id})
        report = report.model_copy(update={"report_hash": report.compute_hash()})

        can_execute = report.dag_valid and report.bounds_respected and len(report.policy_violations) == 0
        return SimulateCompositionResponse(report=report, can_execute=can_execute)

    def submit(self, request: ExplicitCompositionRequest) -> SubmitCompositionResponse:
        """Forward approved composition to PI Core.

        Each ``CompositionNode`` becomes a goal dispatched through
        ``PiOrchestrator.execute_goal``. All resulting ``ExecutionTrace``
        rows share ``trace_id = ledger_<request_id>`` so the replay
        endpoint can reconstruct the run with a single ledger query.
        """
        core_ledger_id = f"ledger_{request.request_id}"
        # No real orchestrator wired in this process — return a soft
        # QUEUED response so the boundary still works during tests.
        if self._orchestrator is None or self._ledger is None:
            return SubmitCompositionResponse(
                request_id=request.request_id,
                accepted=True,
                status="QUEUED",
                message="Composition queued (core unavailable; in-memory stub)",
                core_ledger_id=core_ledger_id,
                estimated_execution_time_ms=request.global_bounds.get("max_execution_time_ms", 300_000),
            )

        from pi_agent_chain.models import ExecutionTrace
        from pi_micro_agents.orchestrator.core import OrchestratorInput

        start = time.perf_counter()
        anomalies: List[str] = []
        all_success = True
        for node in request.nodes:
            artifact = node.artifacts[0] if node.artifacts else {}
            if not isinstance(artifact, dict):
                artifact = {}
            # Route on the artifact's goal (the keyword the Builder/Compose UI
            # set) so the chosen micro-agent actually runs. Without this the
            # orchestrator routes on a synthetic descriptor and always falls back
            # to PiMasterGeneralistFallback.
            goal = artifact.get("goal") or f"{node.operation} on {node.runtime} for {node.node_id}"
            ctx: Dict[str, Any] = {
                "node_id": node.node_id,
                "runtime": node.runtime,
                "operation": node.operation,
                "artifacts": list(node.artifacts),
                "tenant_id": request.tenant_id,
                "schema_version": node.required_schema_version,
            }
            # Lift artifact fields (content, filename, solidity_code, …) to the
            # top level so each agent's input_factory (ctx.get("content"), etc.)
            # receives them. Reserved keys above are not overwritten.
            for _k, _v in artifact.items():
                if _k != "goal":
                    ctx.setdefault(_k, _v)
            try:
                envelope = OrchestratorInput(goal=goal, context=ctx)
                result = self._orchestrator.execute_goal(envelope)
                payload_hash = hashlib.sha256(json.dumps(ctx, sort_keys=True, default=str).encode()).hexdigest()
                trace = ExecutionTrace(
                    trace_id=core_ledger_id,
                    node_name=f"{node.runtime}:{node.operation}:{node.node_id}",
                    input_payload_hash=payload_hash,
                    llm_seed=1337,
                    llm_temperature=0.0,
                    raw_output=result.model_dump_json(),
                    is_valid_type=result.success,
                    error_message=", ".join(result.anomalies_detected) or None,
                )
                self._ledger.append(trace)
                all_success = all_success and result.success
                anomalies.extend(result.anomalies_detected or [])
            except Exception as e:
                _services_logger.exception("submit failed for node %s", node.node_id)
                payload_hash = hashlib.sha256(json.dumps(ctx, sort_keys=True, default=str).encode()).hexdigest()
                trace = ExecutionTrace(
                    trace_id=core_ledger_id,
                    node_name=f"{node.runtime}:{node.operation}:{node.node_id}",
                    input_payload_hash=payload_hash,
                    llm_seed=1337,
                    llm_temperature=0.0,
                    raw_output=json.dumps({"error": str(e)}),
                    is_valid_type=False,
                    error_message=f"{type(e).__name__}: {e}",
                )
                self._ledger.append(trace)
                all_success = False
                anomalies.append(f"node_{node.node_id}_error")

        elapsed_ms = int((time.perf_counter() - start) * 1000)
        return SubmitCompositionResponse(
            request_id=request.request_id,
            accepted=all_success,
            status="ACCEPTED" if all_success else "REJECTED",
            message=(
                "Composition executed against PI Core"
                if all_success
                else f"Composition executed with anomalies: {', '.join(anomalies[:5])}"
            ),
            core_ledger_id=core_ledger_id,
            estimated_execution_time_ms=max(elapsed_ms, 1),
        )

    def get_execution_replay(
        self,
        ledger_id: str,
        from_seq: Optional[int] = None,
        to_seq: Optional[int] = None,
    ) -> GetExecutionReplayResponse:
        """Fetch replay events for a prior submission from the StateLedger.

        ``ledger_id`` is the value previously returned by ``submit()`` and
        is used as the ``trace_id`` joining all ExecutionTrace rows of
        that submission. Replay events are deterministically hash-chained.
        """
        if self._ledger is None:
            return GetExecutionReplayResponse(
                ledger_id=ledger_id,
                events=[],
                integrity_verified=False,
                total_events=0,
            )

        traces = self._ledger.get_trace(ledger_id)
        events: List[ExecutionReplayEvent] = []
        previous_hash = ""
        integrity_ok = True
        for idx, trace in enumerate(traces, start=1):
            # Each event hash chains over the previous hash plus the trace
            # input hash — same canonical form the orchestrator produces.
            chain_input = f"{previous_hash}:{trace.input_payload_hash}".encode()
            event_hash = hashlib.sha256(chain_input).hexdigest()
            events.append(
                ExecutionReplayEvent(
                    sequence_number=idx,
                    event_type="EXECUTION_TRACE" if trace.is_valid_type else "EXECUTION_FAILED",
                    emitted_by=trace.node_name,
                    emitted_at=trace.timestamp.isoformat()
                    if hasattr(trace.timestamp, "isoformat")
                    else str(trace.timestamp),
                    event_hash=event_hash,
                    previous_hash=previous_hash,
                    payload_summary={
                        "input_payload_hash": trace.input_payload_hash,
                        "error_message": trace.error_message,
                        "valid": trace.is_valid_type,
                    },
                )
            )
            if trace.error_message:
                integrity_ok = False
            previous_hash = event_hash

        if from_seq is not None:
            events = [e for e in events if e.sequence_number >= from_seq]
        if to_seq is not None:
            events = [e for e in events if e.sequence_number <= to_seq]
        return GetExecutionReplayResponse(
            ledger_id=ledger_id,
            events=events,
            integrity_verified=integrity_ok,
            total_events=len(events),
        )

    def list_capabilities(
        self,
        tenant_id: str,
        runtime_filter: Optional[str] = None,
        operation_filter: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> ListMarketplaceCapabilitiesResponse:
        """Query the live AgentRouter registry.

        Every registered micro-agent is surfaced as a MarketplaceCapability
        under the ``pi-extension-governor`` runtime tier with ``SANDBOX``
        operation — that's how the console's strict Literal types match the
        sandboxed/extension nature of the agent catalogue.
        """
        try:
            from pi_micro_agents.orchestrator.router import AgentRouter
        except Exception as e:
            _services_logger.warning("AgentRouter unavailable: %s — returning empty catalogue", e)
            return ListMarketplaceCapabilitiesResponse(
                capabilities=[],
                total=0,
                limit=limit,
                offset=offset,
            )

        all_caps: List[MarketplaceCapability] = []
        for route in AgentRouter.routes:
            # Prefer the agent class's docstring as a human-readable description
            # (e.g. "CI/CD dependency and security patch scanner") over the raw
            # "AgentName — keywords:" dump. Strip "Agent N:" prefixes and take the
            # first sentence/line; fall back to the keywords if there's no doc.
            doc = (getattr(route.agent_class, "__doc__", "") or "").strip()
            first_line = doc.split("\n", 1)[0].strip()
            first_line = re.sub(r"^Agent\s+\d+[:\-]\s*", "", first_line)
            description = first_line or ("Checks: " + ", ".join(route.keywords[:4]))
            cap = MarketplaceCapability(
                capability_id=f"cap_{route.agent_name.lower()}",
                agent_name=route.agent_name,
                runtime="pi-extension-governor",
                operation="SANDBOX",
                description=description,
                schema_version="1.0.0",
                trust_tier="GOVERNED",
                compatibility_tags=route.keywords,
                deterministic_bounds={"max_depth": 1, "max_fanout": 1},
            )
            all_caps.append(cap)

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

    def get_compatibility_graph(
        self, tenant_id: str, runtime_filter: Optional[str] = None
    ) -> GetCompatibilityGraphResponse:
        """Derive a compatibility graph from the live AgentRouter registry.

        Each registered micro-agent becomes a node. Two agents are
        considered compatible (edge ``compatible=True``) iff they share at
        least one routing keyword — that's the same signal the AgentRouter
        uses to dispatch goals, so it's the authoritative "can these flow
        into one another" relation we can derive without instrumenting
        every micro-agent for explicit declarations.

        The graph is bounded (default 32 nodes / 96 edges) because the
        full 243-agent graph would have thousands of edges. Use
        ``runtime_filter`` to narrow further.
        """
        try:
            from pi_micro_agents.orchestrator.router import AgentRouter
        except Exception as e:  # pragma: no cover — partial install
            _services_logger.warning("AgentRouter unavailable for compatibility-graph: %s", e)
            return GetCompatibilityGraphResponse(nodes=[], edges=[])

        max_nodes = 32
        routes = list(AgentRouter.routes)[:max_nodes]

        nodes: List[CompatibilityNode] = [
            CompatibilityNode(
                capability_id=f"cap_{route.agent_name.lower()}",
                runtime="pi-extension-governor",
                trust_tier="GOVERNED",
            )
            for route in routes
        ]

        edges: List[CompatibilityEdge] = []
        for i, a in enumerate(routes):
            kw_a = set(a.keywords)
            for b in routes[i + 1 :]:
                shared = kw_a & set(b.keywords)
                if not shared:
                    continue
                edges.append(
                    CompatibilityEdge(
                        source_capability=f"cap_{a.agent_name.lower()}",
                        target_capability=f"cap_{b.agent_name.lower()}",
                        compatible=True,
                        reason=f"shared keywords: {', '.join(sorted(shared)[:3])}",
                    )
                )
                if len(edges) >= 96:
                    break
            if len(edges) >= 96:
                break

        if runtime_filter:
            nodes = [n for n in nodes if n.runtime == runtime_filter]
            node_ids = {n.capability_id for n in nodes}
            edges = [e for e in edges if e.source_capability in node_ids and e.target_capability in node_ids]
        return GetCompatibilityGraphResponse(nodes=nodes, edges=edges)

    def health_probe(self) -> Dict[str, bool]:
        """Real ledger + orchestrator reachability check.

        Returns a dict with boolean liveness for each backing surface.
        Never raises — callers can shape the response themselves.
        """
        ledger_ok = False
        if self._ledger is not None:
            try:
                with self._ledger._conn() as conn:  # type: ignore[attr-defined]
                    conn.execute("SELECT 1").fetchone()
                ledger_ok = True
            except Exception as e:
                _services_logger.warning("ledger probe failed: %s", e)

        orchestrator_ok = self._orchestrator is not None

        registry_ok = False
        try:
            from pi_micro_agents.orchestrator.router import AgentRouter

            registry_ok = len(AgentRouter.routes) > 0
        except Exception as e:
            _services_logger.warning("router registry probe failed: %s", e)

        return {
            "core_reachable": orchestrator_ok,
            "ledger_storage_reachable": ledger_ok,
            "schema_registry_reachable": registry_ok,
        }
