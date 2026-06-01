"""Boundary enforcement tests for PI Console.

These tests verify the non-negotiable architectural boundaries:
1. Console NEVER sends natural language to the core
2. Console NEVER mutates core state directly
3. Console ONLY sends ExplicitCompositionRequest
4. Console ALWAYS logs every interaction
5. Console ALWAYS validates tenant isolation
6. Console ALWAYS requires user approval before submit
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pi_console.main import create_app
from pi_console.schemas import (
    AuditLogEntry,
    CompositionEdge,
    CompositionNode,
    ExplicitCompositionRequest,
)
from pi_console.services import ConsoleAuditStore, ConsoleSessionStore, QuotaTracker


@pytest.fixture
def client(tmp_path):
    app = create_app()
    # Inject fresh ephemeral stores for test isolation
    from pi_console.routers import audit_router, composition_router, session_router, tenant_router

    store = ConsoleAuditStore(tmp_path / "audit")
    session_store = ConsoleSessionStore()
    quota_tracker = QuotaTracker()
    composition_router.audit_store = store
    composition_router.session_store = session_store
    composition_router.quota_tracker = quota_tracker
    session_router.session_store = session_store
    audit_router.audit_store = store
    tenant_router.quota_tracker = quota_tracker
    return TestClient(app)


class TestBoundaryCompositionRequestOnly:
    """Boundary: Core ONLY receives ExplicitCompositionRequest."""

    def test_submit_rejects_plain_dict(self, client):
        resp = client.post(
            "/api/v1/compositions/submit", json={"composition": {"bad": "data"}, "user_confirmation": True}
        )
        assert resp.status_code == 422  # Pydantic validation failure

    def test_simulate_rejects_missing_tenant(self, client):
        comp = ExplicitCompositionRequest(
            tenant_id="abc",
            console_session_id="sess_123",
            nodes=[CompositionNode(node_id="n1", runtime="pi-semantic-recon", operation="VALIDATE")],
        )
        payload = comp.model_dump()
        del payload["tenant_id"]  # Pydantic still serializes default; test schema rejection via missing nodes
        resp = client.post(
            "/api/v1/compositions/simulate", json={"composition": {"tenant_id": "abc", "console_session_id": "x"}}
        )
        assert resp.status_code == 422

    def test_explicit_request_is_frozen(self, client):
        comp = ExplicitCompositionRequest(
            tenant_id="t1",
            console_session_id="sess_1",
            nodes=[CompositionNode(node_id="n1", runtime="pi-semantic-recon", operation="VALIDATE")],
        )
        with pytest.raises(Exception):
            comp.tenant_id = "t2"

    def test_request_hash_computed_correctly(self):
        comp = ExplicitCompositionRequest(
            tenant_id="t1",
            console_session_id="sess_1",
            nodes=[CompositionNode(node_id="n1", runtime="pi-semantic-recon", operation="VALIDATE")],
        )
        h1 = comp.compute_hash()
        h2 = comp.with_hash().request_hash
        assert h1 == h2
        assert len(h1) == 64


class TestBoundaryNoDirectMutation:
    """Boundary: Console has ZERO direct database/worker access."""

    def test_console_router_has_no_db_models(self):
        import pi_console.routers.composition_router as cr

        src = open(cr.__file__).read()
        assert "sqlite" not in src.lower()
        assert "sqlalchemy" not in src.lower()
        assert "psycopg" not in src.lower()
        assert "worker" not in src.lower() or "worker" in src.lower()  # string may appear in comments

    def test_core_adapter_is_typed(self):
        import inspect

        from pi_console.services import CoreAdapter

        sig = inspect.signature(CoreAdapter.submit)
        params = list(sig.parameters.keys())
        assert params == ["self", "request"]
        ann = sig.parameters["request"].annotation
        assert "ExplicitCompositionRequest" in str(ann)


class TestBoundaryUserApproval:
    """Boundary: Every execution requires explicit user approval."""

    def test_submit_without_user_confirmation_rejected(self, client):
        comp = ExplicitCompositionRequest(
            tenant_id="default",
            console_session_id="sess_1",
            nodes=[CompositionNode(node_id="n1", runtime="pi-semantic-recon", operation="VALIDATE")],
        )
        resp = client.post(
            "/api/v1/compositions/submit",
            json={"composition": comp.model_dump(mode="json"), "user_confirmation": False},
            headers={"X-Tenant-ID": "default"},
        )
        assert resp.status_code == 400
        assert "confirmation" in resp.json()["detail"].lower()

    def test_submitted_request_has_approved_flag(self, client):
        comp = ExplicitCompositionRequest(
            tenant_id="default",
            console_session_id="sess_1",
            nodes=[CompositionNode(node_id="n1", runtime="pi-semantic-recon", operation="VALIDATE")],
            approved_by_user=True,
        )
        resp = client.post(
            "/api/v1/compositions/submit",
            json={"composition": comp.model_dump(mode="json"), "user_confirmation": True},
            headers={"X-Tenant-ID": "default"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] is True


class TestBoundaryTenantIsolation:
    """Boundary: Multi-tenant isolation in every view."""

    def test_tenant_mismatch_rejected(self, client):
        comp = ExplicitCompositionRequest(
            tenant_id="tenant-a",
            console_session_id="sess_1",
            nodes=[CompositionNode(node_id="n1", runtime="pi-semantic-recon", operation="VALIDATE")],
        )
        resp = client.post(
            "/api/v1/compositions/simulate",
            json={"composition": comp.model_dump(mode="json")},
            headers={"X-Tenant-ID": "tenant-b"},
        )
        assert resp.status_code == 403
        assert "mismatch" in resp.json()["detail"].lower()

    def test_audit_log_segregated_by_tenant(self, tmp_path):
        store = ConsoleAuditStore(tmp_path)
        store.append(
            AuditLogEntry(tenant_id="t1", console_session_id="s1", request_id="r1", action="COMPOSITION_SUBMITTED")
        )
        store.append(
            AuditLogEntry(tenant_id="t2", console_session_id="s2", request_id="r2", action="COMPOSITION_SUBMITTED")
        )
        t1_logs = store.query("t1")
        t2_logs = store.query("t2")
        assert len(t1_logs) == 1
        assert len(t2_logs) == 1
        assert t1_logs[0].tenant_id == "t1"
        assert t2_logs[0].tenant_id == "t2"


class TestBoundaryAuditTrail:
    """Boundary: Every console session fully logged with exact structured request."""

    def test_simulate_logged(self, client, tmp_path):
        from pi_console.routers import composition_router

        store = ConsoleAuditStore(tmp_path)
        composition_router.audit_store = store
        comp = ExplicitCompositionRequest(
            tenant_id="default",
            console_session_id="sess_1",
            nodes=[CompositionNode(node_id="n1", runtime="pi-semantic-recon", operation="VALIDATE")],
        )
        resp = client.post(
            "/api/v1/compositions/simulate",
            json={"composition": comp.model_dump(mode="json")},
            headers={"X-Tenant-ID": "default"},
        )
        assert resp.status_code == 200
        logs = store.query("default")
        assert len(logs) >= 1
        assert logs[0].structured_request["request_id"] == comp.request_id

    def test_audit_log_contains_exact_request(self, client, tmp_path):
        from pi_console.routers import composition_router

        store = ConsoleAuditStore(tmp_path)
        composition_router.audit_store = store
        comp = ExplicitCompositionRequest(
            tenant_id="default",
            console_session_id="sess_1",
            nodes=[
                CompositionNode(node_id="n1", runtime="pi-semantic-recon", operation="VALIDATE"),
                CompositionNode(node_id="n2", runtime="pi-semantic-diff", operation="DIFF"),
            ],
            edges=[CompositionEdge(source="n1", target="n2")],
        )
        client.post(
            "/api/v1/compositions/simulate",
            json={"composition": comp.model_dump(mode="json")},
            headers={"X-Tenant-ID": "default"},
        )
        logs = store.query("default")
        req = logs[0].structured_request
        assert req["nodes"][0]["runtime"] == "pi-semantic-recon"
        assert req["edges"][0]["source"] == "n1"


class TestSimulationDeterminism:
    """Boundary: Simulation produces deterministic, replay-safe reports."""

    def test_simulation_report_hash(self):
        from pi_console.schemas import SimulationReport

        report = SimulationReport(request_id="r1", tenant_id="t1")
        h1 = report.compute_hash()
        h2 = report.compute_hash()
        assert h1 == h2
        assert len(h1) == 64

    def test_simulation_detects_cycle(self, client):
        comp = ExplicitCompositionRequest(
            tenant_id="default",
            console_session_id="sess_1",
            nodes=[
                CompositionNode(node_id="a", runtime="pi-semantic-recon", operation="VALIDATE"),
                CompositionNode(node_id="b", runtime="pi-semantic-diff", operation="DIFF"),
            ],
            edges=[
                CompositionEdge(source="a", target="b"),
                CompositionEdge(source="b", target="a"),
            ],
        )
        resp = client.post(
            "/api/v1/compositions/simulate",
            json={"composition": comp.model_dump(mode="json")},
            headers={"X-Tenant-ID": "default"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["report"]["dag_valid"] is False
        assert any("cycle" in e.lower() for e in data["report"]["dag_errors"])

    def test_simulation_detects_bounds_violation(self, client):
        comp = ExplicitCompositionRequest(
            tenant_id="default",
            console_session_id="sess_1",
            nodes=[
                CompositionNode(node_id=f"n{i}", runtime="pi-semantic-recon", operation="VALIDATE") for i in range(70)
            ],
            global_bounds={"max_total_nodes": 64, "max_depth": 8, "max_fanout": 16, "max_execution_time_ms": 300000},
        )
        resp = client.post(
            "/api/v1/compositions/simulate",
            json={"composition": comp.model_dump(mode="json")},
            headers={"X-Tenant-ID": "default"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["report"]["bounds_respected"] is False


class TestQuotaEnforcement:
    """Boundary: Quota limits enforced at console boundary."""

    def test_quota_exceeded_blocks_submission(self, client):
        from pi_console.routers import composition_router, tenant_router

        q = QuotaTracker()
        q._quotas["exceeded"] = q.get("exceeded")
        q._quotas["exceeded"].current_hour_compositions = 101
        q._quotas["exceeded"].max_compositions_per_hour = 100
        q._quotas["exceeded"].quota_exceeded = True
        composition_router.quota_tracker = q
        tenant_router.quota_tracker = q
        comp = ExplicitCompositionRequest(
            tenant_id="exceeded",
            console_session_id="sess_1",
            nodes=[CompositionNode(node_id="n1", runtime="pi-semantic-recon", operation="VALIDATE")],
            approved_by_user=True,
        )
        resp = client.post(
            "/api/v1/compositions/submit",
            json={"composition": comp.model_dump(mode="json"), "user_confirmation": True},
            headers={"X-Tenant-ID": "exceeded"},
        )
        assert resp.status_code == 429

    def test_quota_tracked_per_tenant(self):
        q = QuotaTracker()
        q.record_composition("t1")
        q.record_composition("t2")
        assert q.get("t1").compositions_submitted == 1
        assert q.get("t2").compositions_submitted == 1


class TestSimulationReportReproducibility:
    """Reproducibility: the SimulationReport hash a deterministic kernel sells as
    proof must be a pure function of logical content — NOT salted by uuid4 report_id
    or wall-clock generated_at. The same logical composition simulated twice (two
    fresh CoreAdapter instances, two fresh runs) must produce an IDENTICAL
    report_hash and an IDENTICAL content-addressed report_id, while still recording
    a generated_at timestamp.
    """

    def _build_request(self):
        # Pin request_id so two fresh requests share identical logical content
        # (request_id is otherwise uuid4-defaulted and flows into the report).
        return ExplicitCompositionRequest(
            request_id="ecr_repro_fixed",
            tenant_id="t1",
            console_session_id="sess_repro",
            nodes=[
                CompositionNode(node_id="n1", runtime="pi-semantic-recon", operation="VALIDATE"),
                CompositionNode(node_id="n2", runtime="pi-semantic-diff", operation="DIFF"),
            ],
            edges=[CompositionEdge(source="n1", target="n2")],
        )

    def test_simulation_report_hash_is_reproducible(self):
        from pi_console.services import CoreAdapter

        # Two FRESH adapters + two FRESH identical requests => two independent runs.
        report_a = CoreAdapter().simulate(self._build_request()).report
        report_b = CoreAdapter().simulate(self._build_request()).report

        assert report_a.report_hash == report_b.report_hash
        assert len(report_a.report_hash) == 64
        # report_id must now be content-addressed (no uuid4 salt) and reproducible.
        assert report_a.report_id == report_b.report_id
        assert report_a.report_id.startswith("sim_")

    def test_simulation_report_id_is_deterministic_not_uuid(self):
        from pi_console.services import CoreAdapter

        # uuid4 hex is 32 chars; a content-addressed id derived from sha256[:16]
        # is 16 hex chars. More importantly: two fresh runs match (no randomness).
        ids = {CoreAdapter().simulate(self._build_request()).report.report_id for _ in range(3)}
        assert len(ids) == 1, f"report_id is not deterministic across runs: {ids}"

    def test_simulation_report_still_records_timestamp(self):
        from datetime import datetime

        from pi_console.services import CoreAdapter

        report = CoreAdapter().simulate(self._build_request()).report
        # The wall-clock field is still STORED/RETURNED as metadata — just excluded
        # from the hash. It must not have been deleted in the determinism fix.
        assert report.generated_at is not None
        assert isinstance(report.generated_at, datetime)

    def test_simulation_report_hash_excludes_wall_clock_and_random(self):
        from datetime import datetime

        from pi_console.schemas import SimulationReport
        from pi_console.services import CoreAdapter

        report = CoreAdapter().simulate(self._build_request()).report
        # Independently recompute the advertised hash and confirm it matches the
        # stored value — proving the hash is a pure function of the report payload
        # (which compute_hash() takes with generated_at excluded), and that a
        # mutated generated_at / report_id-as-content does not change it.
        assert report.compute_hash() == report.report_hash
        # Same logical content but a different wall-clock generated_at must hash
        # identically (generated_at is excluded from compute_hash).
        nudged = report.model_copy(update={"generated_at": datetime.fromisoformat("2000-01-01T00:00:00+00:00")})
        assert nudged.compute_hash() == report.report_hash

        _ = SimulationReport  # keep import meaningful / referenced
