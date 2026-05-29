"""Production Hardening Conformance Tests.

Tests covering persistent storage, security, telemetry, API layer,
and deployment readiness. All deterministic, zero randomness.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import time

import pytest

from pi_production.security.auth import (
    AuthenticationError,
    JWTToken,
    RBACPolicy,
    RequestSigner,
    SecretManager,
    SecurityContext,
    SignatureError,
)
from pi_production.storage.engine import (
    AuditLogger,
    ConnectionPool,
    HealthRecorder,
    ReceiptPersister,
    SnapshotPersister,
    TenantRegistry,
    install_append_only_triggers,
)
from pi_production.telemetry.metrics import (
    MetricsRegistry,
    StructuredLogger,
    TelemetryManager,
    Tracer,
)

# ──────────────────────────────
#  Storage Layer Fixtures
# ──────────────────────────────


@pytest.fixture
def db_pool():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    pool = ConnectionPool(path)
    install_append_only_triggers(pool)
    yield pool
    os.unlink(path)


# ──────────────────────────────
#  Snapshot Persistence Tests
# ──────────────────────────────


class TestSnapshotPersistence:
    def test_persist_and_retrieve(self, db_pool):
        sp = SnapshotPersister(db_pool)
        sp.persist("snap_1", "t1", "src_a", "CONFIG", "2026-06-01T12:00:00Z", 1, "ph1", "{}", "")
        latest = sp.get_latest("t1", "src_a", "CONFIG")
        assert latest is not None
        assert latest["snapshot_id"] == "snap_1"

    def test_tenant_isolation(self, db_pool):
        sp = SnapshotPersister(db_pool)
        sp.persist("snap_t1", "t1", "src", "CONFIG", "2026-06-01T12:00:00Z", 1, "ph", "{}", "")
        sp.persist("snap_t2", "t2", "src", "CONFIG", "2026-06-01T12:00:00Z", 1, "ph", "{}", "")
        t1 = sp.get_latest("t1", "src", "CONFIG")
        t2 = sp.get_latest("t2", "src", "CONFIG")
        assert t1 is not None and t1["snapshot_id"] == "snap_t1"
        assert t2 is not None and t2["snapshot_id"] == "snap_t2"

    def test_chain_retrieval_ordered(self, db_pool):
        sp = SnapshotPersister(db_pool)
        prev = ""
        for i in range(3):
            sid = f"snap_{i}"
            ph = hashlib.sha256(f"data{i}".encode()).hexdigest()
            sp.persist(sid, "t1", "src", "CONFIG", f"2026-06-01T12:00:0{i}Z", i + 1, ph, "{}", prev)
            latest = sp.get_latest("t1", "src", "CONFIG")
            assert latest is not None
            prev = latest["artifact_hash"]
        chain = sp.get_chain("t1", "src", "CONFIG")
        assert len(chain) == 3
        assert chain[0]["snapshot_id"] == "snap_0"
        assert chain[2]["snapshot_id"] == "snap_2"

    def test_integrity_verification_passes(self, db_pool):
        sp = SnapshotPersister(db_pool)
        sp.persist("snap_1", "t1", "src", "CONFIG", "2026-06-01T12:00:00Z", 1, "ph1", "{}", "")
        ok, errors = sp.verify_chain("t1", "src", "CONFIG")
        assert ok is True
        assert errors == []

    def test_mutation_update_blocked(self, db_pool):
        install_append_only_triggers(db_pool)
        sp = SnapshotPersister(db_pool)
        sp.persist("snap_1", "t1", "src", "CONFIG", "2026-06-01T12:00:00Z", 1, "ph1", "{}", "")
        with pytest.raises(Exception) as exc:
            db_pool.execute_write("UPDATE snapshots SET payload_hash = 'tampered' WHERE snapshot_id = ?", ("snap_1",))
        assert "MUTATION_FORBIDDEN" in str(exc.value)

    def test_mutation_delete_blocked(self, db_pool):
        install_append_only_triggers(db_pool)
        sp = SnapshotPersister(db_pool)
        sp.persist("snap_1", "t1", "src", "CONFIG", "2026-06-01T12:00:00Z", 1, "ph1", "{}", "")
        with pytest.raises(Exception) as exc:
            db_pool.execute_write("DELETE FROM snapshots WHERE snapshot_id = ?", ("snap_1",))
        assert "MUTATION_FORBIDDEN" in str(exc.value)

    def test_artifact_hash_computed(self, db_pool):
        sp = SnapshotPersister(db_pool)
        sp.persist("snap_1", "t1", "src", "CONFIG", "2026-06-01T12:00:00Z", 1, "ph1", "{}", "")
        latest = sp.get_latest("t1", "src", "CONFIG")
        assert latest is not None
        assert latest["artifact_hash"] != ""
        assert len(latest["artifact_hash"]) == 64


# ──────────────────────────────
#  Audit Logger Tests
# ──────────────────────────────


class TestAuditLogger:
    def test_log_and_query(self, db_pool):
        al = AuditLogger(db_pool)
        aid = al.log("t1", "actor_1", "API", "snapshot:store", "snapshot", "snap_1", {}, {}, "corr_1")
        assert aid.startswith("audit_t1_actor_1")
        entries = al.query("t1", limit=10)
        assert len(entries) == 1
        assert entries[0]["action"] == "snapshot:store"

    def test_audit_hash_chain(self, db_pool):
        al = AuditLogger(db_pool)
        al.log("t1", "a", "API", "action_1", "res", "r1", {}, {}, "c1")
        al.log("t1", "a", "API", "action_2", "res", "r2", {}, {}, "c2")
        entries = al.query("t1", limit=10)
        assert len(entries) == 2
        # Second entry should reference first hash
        assert entries[0]["previous_audit_hash"] == entries[1]["audit_hash"]

    def test_tenant_isolation(self, db_pool):
        al = AuditLogger(db_pool)
        al.log("t1", "a", "API", "act", "res", "r", {}, {}, "c")
        al.log("t2", "a", "API", "act", "res", "r", {}, {}, "c")
        assert len(al.query("t1")) == 1
        assert len(al.query("t2")) == 1

    def test_correlation_index(self, db_pool):
        al = AuditLogger(db_pool)
        al.log("t1", "a", "API", "act", "res", "r", {}, {}, "corr_x")
        rows = db_pool.execute_read("SELECT * FROM audit_log WHERE correlation_id = ?", ("corr_x",))
        assert len(rows) == 1


# ──────────────────────────────
#  Receipt Persister Tests
# ──────────────────────────────


class TestReceiptPersister:
    def test_persist_and_get(self, db_pool):
        rp = ReceiptPersister(db_pool)
        rp.persist("r1", "t1", "w1", "DIFF", "SUCCESS", "ih", "dp", ["slot_1"], "ph", "2026-06-01T12:00:00Z")
        entries = rp.get_by_tenant("t1")
        assert len(entries) == 1
        assert entries[0]["receipt_id"] == "r1"

    def test_append_only_no_update(self, db_pool):
        install_append_only_triggers(db_pool)
        rp = ReceiptPersister(db_pool)
        rp.persist("r1", "t1", "w1", "DIFF", "SUCCESS", "ih", "dp", [], "ph", "2026-06-01T12:00:00Z")
        with pytest.raises(Exception) as exc:
            db_pool.execute_write("UPDATE receipts SET status = 'tampered' WHERE receipt_id = ?", ("r1",))
        assert "MUTATION_FORBIDDEN" in str(exc.value)


# ──────────────────────────────
#  Tenant Registry Tests
# ──────────────────────────────


class TestTenantRegistry:
    def test_register_and_get(self, db_pool):
        tr = TenantRegistry(db_pool)
        tr.register("tenant_a", "Tenant A", {"retention": 30}, {"compositions_per_hour": 100})
        t = tr.get("tenant_a")
        assert t is not None
        assert t["tenant_name"] == "Tenant A"

    def test_is_active(self, db_pool):
        tr = TenantRegistry(db_pool)
        tr.register("t1", "T1", {}, {})
        assert tr.is_active("t1") is True
        assert tr.is_active("nonexistent") is False

    def test_idempotent_registration(self, db_pool):
        tr = TenantRegistry(db_pool)
        tr.register("t1", "T1", {}, {})
        tr.register("t1", "T1-Updated", {}, {})
        t = tr.get("t1")
        assert t["tenant_name"] == "T1"  # ON CONFLICT DO NOTHING


# ──────────────────────────────
#  Health Recorder Tests
# ──────────────────────────────


class TestHealthRecorder:
    def test_record_and_latest(self, db_pool):
        hr = HealthRecorder(db_pool)
        hr.record("storage", "HEALTHY", "DB initialized")
        latest = hr.latest("storage")
        assert latest is not None
        assert latest["status"] == "HEALTHY"

    def test_status_summary(self, db_pool):
        hr = HealthRecorder(db_pool)
        hr.record("storage", "HEALTHY")
        hr.record("api", "HEALTHY")
        summary = hr.status_summary()
        assert summary["overall"] == "HEALTHY"
        assert "storage" in summary["components"]
        assert "api" in summary["components"]

    def test_degraded_overall(self, db_pool):
        hr = HealthRecorder(db_pool)
        hr.record("storage", "HEALTHY")
        hr.record("api", "DEGRADED")
        summary = hr.status_summary()
        assert summary["overall"] == "DEGRADED"


# ──────────────────────────────
#  JWT Security Tests
# ──────────────────────────────


class TestJWTToken:
    def test_encode_decode(self):
        jwt = JWTToken("test-secret-key-32bytes-long")
        claims = {"sub": "user_1", "tenant_id": "t1", "role": "operator"}
        token = jwt.encode(claims, ttl_seconds=3600)
        decoded = jwt.decode(token)
        assert decoded["sub"] == "user_1"
        assert decoded["tenant_id"] == "t1"

    def test_expired_token_rejected(self):
        jwt = JWTToken("secret")
        token = jwt.encode({"sub": "u"}, ttl_seconds=-1)
        with pytest.raises(AuthenticationError) as exc:
            jwt.decode(token)
        assert "expired" in str(exc.value)

    def test_invalid_signature_rejected(self):
        jwt = JWTToken("secret_a")
        token = jwt.encode({"sub": "u"})
        jwt_b = JWTToken("secret_b")
        with pytest.raises(AuthenticationError) as exc:
            jwt_b.decode(token)
        assert "signature" in str(exc.value)

    def test_deterministic_jti(self):
        jwt = JWTToken("secret")
        t1 = jwt.encode({"sub": "u"})
        t2 = jwt.encode({"sub": "u"})
        # JTI is deterministic based on claims
        d1 = jwt.decode(t1)
        d2 = jwt.decode(t2)
        assert d1["jti"] == d2["jti"]


# ──────────────────────────────
#  Request Signer Tests
# ──────────────────────────────


class TestRequestSigner:
    def test_sign_and_verify(self):
        signer = RequestSigner("secret-key")
        sig = signer.sign("POST", "/v1/compositions", int(time.time()), "t1", b'{"a":1}')
        assert len(sig) == 64

    def test_verify_valid(self):
        signer = RequestSigner("secret-key")
        ts = int(time.time())
        sig = signer.sign("POST", "/v1/compositions", ts, "t1", b'{"a":1}')
        signer.verify(sig, "POST", "/v1/compositions", ts, "t1", b'{"a":1}')

    def test_verify_bad_signature(self):
        signer = RequestSigner("secret-key")
        ts = int(time.time())
        with pytest.raises(SignatureError) as exc:
            signer.verify("bad_sig", "POST", "/v1/compositions", ts, "t1", b'{"a":1}')
        assert "signature_mismatch" in str(exc.value)

    def test_verify_old_timestamp(self):
        signer = RequestSigner("secret-key")
        old_ts = int(time.time()) - 600
        sig = signer.sign("POST", "/v1/compositions", old_ts, "t1", b"")
        with pytest.raises(SignatureError) as exc:
            signer.verify(sig, "POST", "/v1/compositions", old_ts, "t1", b"")
        assert "timestamp" in str(exc.value)


# ──────────────────────────────
#  RBAC Tests
# ──────────────────────────────


class TestRBACPolicy:
    def test_admin_all_permissions(self):
        rbac = RBACPolicy()
        assert rbac.allowed("admin", "anything:at:all") is True

    def test_operator_composition_allowed(self):
        rbac = RBACPolicy()
        assert rbac.allowed("operator", "composition:submit") is True

    def test_viewer_no_submit(self):
        rbac = RBACPolicy()
        assert rbac.allowed("viewer", "composition:submit") is False

    def test_tenant_isolation_enforced(self):
        rbac = RBACPolicy()
        assert rbac.allowed_tenants("admin", "t2", "t1") is True
        assert rbac.allowed_tenants("operator", "t2", "t1") is False


# ──────────────────────────────
#  Secret Manager Tests
# ──────────────────────────────


class TestSecretManager:
    def test_env_fallback(self, monkeypatch):
        monkeypatch.setenv("PI_SECRET_JWT", "env_jwt_value")
        sm = SecretManager()
        assert sm.get("jwt") == "env_jwt_value"

    def test_file_fallback(self, tmp_path):
        secret_file = tmp_path / "jwt"
        secret_file.write_text("file_jwt_value")
        # SecretManager strict mode requires 0600 — write_text uses umask
        # default (typically 0644), so chmod here to satisfy the policy.
        os.chmod(secret_file, 0o600)
        sm = SecretManager(str(tmp_path))
        assert sm.get("jwt") == "file_jwt_value"

    def test_not_found_raises(self):
        sm = SecretManager()
        with pytest.raises(Exception):
            sm.get("nonexistent")

    def test_rotate_generates_valid(self):
        sm = SecretManager()
        s = sm.rotate_secret("test", length=64)
        assert len(s) == 64
        assert all(c.isalnum() or c in "_-" for c in s)


# ──────────────────────────────
#  Telemetry / Metrics Tests
# ──────────────────────────────


class TestMetricsRegistry:
    def test_counter_increment(self):
        m = MetricsRegistry()
        m.counter("requests_total", ["tenant"], {"tenant": "t1"}, 1)
        m.counter("requests_total", ["tenant"], {"tenant": "t1"}, 2)
        output = m.prometheus_format()
        assert 'requests_total{tenant="t1"} 3' in output

    def test_gauge_set(self):
        m = MetricsRegistry()
        m.gauge("active_sessions", ["tenant"], {"tenant": "t1"}, 5.0)
        output = m.prometheus_format()
        assert 'active_sessions{tenant="t1"} 5.0' in output

    def test_histogram_record(self):
        m = MetricsRegistry()
        m.histogram("request_duration_ms", ["tenant"], {"tenant": "t1"}, 12.5)
        m.histogram("request_duration_ms", ["tenant"], {"tenant": "t1"}, 7.5)
        output = m.prometheus_format()
        assert 'request_duration_ms_count{tenant="t1"} 2' in output
        assert 'request_duration_ms_sum{tenant="t1"} 20.0' in output

    def test_prometheus_format_valid(self):
        m = MetricsRegistry()
        m.counter("c", ["l"], {"l": "v"}, 1)
        output = m.prometheus_format()
        assert output.startswith('# TYPE c counter\nc{l="v"} 1\n')

    def test_thread_safe_counter(self):
        m = MetricsRegistry()

        def worker():
            for _ in range(100):
                m.counter("race_test", ["t"], {"t": "x"}, 1)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        output = m.prometheus_format()
        assert 'race_test{t="x"} 1000' in output


class TestStructuredLogger:
    def test_log_produces_json(self, capsys):
        logger = StructuredLogger("test")
        logger.set_correlation("corr_1")
        entry = logger.info("test_event", key="value")
        captured = capsys.readouterr()
        assert "test_event" in captured.out
        assert "corr_1" in captured.out
        assert entry["correlation_id"] == "corr_1"

    def test_error_level(self, capsys):
        logger = StructuredLogger("test")
        logger.set_correlation("c1")
        logger.error("fail_event", reason="test")
        captured = capsys.readouterr()
        assert "fail_event" in captured.out
        assert "ERROR" in captured.out


class TestTracer:
    def test_start_end_span(self):
        tracer = Tracer("svc")
        span = tracer.start_span("trace_1", "op_a")
        ended = tracer.end_span(span, status="OK")
        assert ended.end_time is not None
        assert ended.status == "OK"
        trace = tracer.get_trace("trace_1")
        assert len(trace) == 1
        assert trace[0]["operation"] == "op_a"

    def test_span_duration_positive(self):
        tracer = Tracer("svc")
        span = tracer.start_span("t", "op")
        time.sleep(0.01)
        tracer.end_span(span)
        trace = tracer.get_trace("t")
        assert trace[0]["duration_ms"] > 0


class TestTelemetryManager:
    def test_request_scope_ok(self):
        tm = TelemetryManager("svc")
        with tm.request_scope("corr_1", "test_op"):
            pass
        trace = tm.tracer.get_trace("corr_1")
        assert len(trace) >= 1
        assert trace[0]["status"] == "OK"

    def test_request_scope_error(self):
        tm = TelemetryManager("svc")
        with pytest.raises(ValueError):
            with tm.request_scope("corr_1", "fail_op"):
                raise ValueError("boom")
        trace = tm.tracer.get_trace("corr_1")
        assert trace[0]["status"] == "ERROR"


# ──────────────────────────────
#  Integration Tests
# ──────────────────────────────


class TestProductionIntegration:
    def test_end_to_end_storage_security_telemetry(self, db_pool):
        # Storage: persist snapshot
        sp = SnapshotPersister(db_pool)
        sp.persist("snap_1", "t1", "src", "CONFIG", "2026-06-01T12:00:00Z", 1, "ph", "{}", "")

        # Security: generate and verify JWT
        jwt = JWTToken("secret")
        token = jwt.encode({"sub": "u1", "tenant_id": "t1", "role": "operator"})
        claims = jwt.decode(token)
        assert claims["tenant_id"] == "t1"

        # Security: RBAC check
        rbac = RBACPolicy()
        assert rbac.allowed(claims["role"], "snapshot:store") is True

        # Telemetry: log with correlation
        logger = StructuredLogger("integration")
        logger.set_correlation("corr_integ")
        logger.info("snapshot_stored", snapshot_id="snap_1")

        # Telemetry: metrics
        metrics = MetricsRegistry()
        metrics.counter("snapshots_stored", ["tenant"], {"tenant": "t1"}, 1)
        prom = metrics.prometheus_format()
        assert 'snapshots_stored{tenant="t1"} 1' in prom

        # Audit: action recorded
        al = AuditLogger(db_pool)
        al.log("t1", "u1", "API", "snapshot:store", "snapshot", "snap_1", {}, {}, "corr_integ")
        audits = al.query("t1")
        assert len(audits) == 1

        # Health: all components healthy
        hr = HealthRecorder(db_pool)
        hr.record("storage", "HEALTHY")
        hr.record("security", "HEALTHY")
        summary = hr.status_summary()
        assert summary["overall"] == "HEALTHY"

    def test_tenant_isolation_full_stack(self, db_pool):
        # Tenant A
        TenantRegistry(db_pool).register("t_a", "Tenant A", {}, {})
        sp = SnapshotPersister(db_pool)
        sp.persist("snap_a", "t_a", "src", "CONFIG", "2026-06-01T12:00:00Z", 1, "ph", "{}", "")
        # Tenant B
        TenantRegistry(db_pool).register("t_b", "Tenant B", {}, {})
        sp.persist("snap_b", "t_b", "src", "CONFIG", "2026-06-01T12:00:00Z", 1, "ph", "{}", "")

        # Verify no cross-tenant leakage
        chain_a = sp.get_chain("t_a", "src", "CONFIG")
        chain_b = sp.get_chain("t_b", "src", "CONFIG")
        assert len(chain_a) == 1
        assert len(chain_b) == 1
        assert chain_a[0]["snapshot_id"] == "snap_a"
        assert chain_b[0]["snapshot_id"] == "snap_b"

    def test_rate_limiter_integration(self, db_pool):
        from pi_production.storage.engine import RateLimiter

        rl = RateLimiter(db_pool, default_max=3, window_seconds=60)
        for i in range(3):
            allowed, info = rl.check("t1", "actor_1")
            assert allowed is True
            assert info["count"] == i + 1
        # 4th request should be blocked
        allowed, info = rl.check("t1", "actor_1")
        assert allowed is False
        assert info["remaining"] == 0

    def test_chain_integrity_under_load(self, db_pool):
        sp = SnapshotPersister(db_pool)
        prev = ""
        for i in range(10):
            sid = f"snap_{i:03d}"
            ph = hashlib.sha256(f"data_{i}".encode()).hexdigest()
            sp.persist(sid, "t1", "src", "CONFIG", f"2026-06-01T12:00:{i:02d}Z", i + 1, ph, json.dumps({"i": i}), prev)
            latest = sp.get_latest("t1", "src", "CONFIG")
            assert latest is not None
            prev = latest["artifact_hash"]

        ok, errors = sp.verify_chain("t1", "src", "CONFIG")
        assert ok is True, f"Integrity errors: {errors}"
        assert len(errors) == 0

    def test_audit_hash_chain_under_load(self, db_pool):
        al = AuditLogger(db_pool)
        for i in range(20):
            al.log("t1", "actor", "API", f"action_{i}", "res", f"r{i}", {}, {}, f"c{i}")
        entries = al.query("t1", limit=100)
        assert len(entries) == 20
        # Verify all entries have non-empty audit hashes
        for e in entries:
            assert e["audit_hash"] != ""
            assert len(e["audit_hash"]) == 64

    def test_concurrent_writes_safe(self, db_pool):
        sp = SnapshotPersister(db_pool)

        def writer(i):
            sp.persist(f"snap_t{i}", "t1", "src", "CONFIG", f"2026-06-01T12:00:{i:02d}Z", i + 1, f"ph{i}", "{}", "")

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        chain = sp.get_chain("t1", "src", "CONFIG")
        assert len(chain) == 10

    def test_storage_and_receipt_persist_both_append_only(self, db_pool):
        sp = SnapshotPersister(db_pool)
        rp = ReceiptPersister(db_pool)
        sp.persist("snap_1", "t1", "src", "CONFIG", "2026-06-01T12:00:00Z", 1, "ph", "{}", "")
        rp.persist("r1", "t1", "w1", "DIFF", "SUCCESS", "ih", "dp", ["s1"], "ph", "2026-06-01T12:00:00Z")

        # Mutation forbidden on both tables
        install_append_only_triggers(db_pool)
        with pytest.raises(Exception):
            db_pool.execute_write("UPDATE snapshots SET payload_hash = 'x' WHERE snapshot_id = 'snap_1'")
        with pytest.raises(Exception):
            db_pool.execute_write("UPDATE receipts SET status = 'x' WHERE receipt_id = 'r1'")

    def test_telemetry_request_scope_captures_error(self):
        tm = TelemetryManager("test")
        with pytest.raises(RuntimeError):
            with tm.request_scope("corr_err", "fail_op"):
                raise RuntimeError("intentional")
        trace = tm.tracer.get_trace("corr_err")
        assert trace[0]["status"] == "ERROR"
        # Metrics should still work
        tm.metrics.counter("errors_total", ["type"], {"type": "RuntimeError"}, 1)

    def test_jwt_and_signer_combined_protection(self):
        jwt = JWTToken("secret")
        signer = RequestSigner("secret")
        claims = {"sub": "u1", "tenant_id": "t1", "role": "operator"}
        token = jwt.encode(claims)
        ts = int(time.time())
        sig = signer.sign("POST", "/v1/compositions", ts, "t1", b'{"a":1}')
        # Verify both
        decoded = jwt.decode(token)
        signer.verify(sig, "POST", "/v1/compositions", ts, "t1", b'{"a":1}')
        assert decoded["sub"] == "u1"

    def test_health_overall_calculated_correctly(self, db_pool):
        hr = HealthRecorder(db_pool)
        hr.record("a", "HEALTHY")
        hr.record("b", "HEALTHY")
        hr.record("c", "HEALTHY")
        assert hr.status_summary()["overall"] == "HEALTHY"

        hr.record("a", "HEALTHY")
        hr.record("b", "DEGRADED")
        hr.record("c", "HEALTHY")
        assert hr.status_summary()["overall"] == "DEGRADED"

    def test_rbac_cross_tenant_blocked_for_non_admin(self):
        rbac = RBACPolicy()
        assert rbac.allowed_tenants("operator", "t2", "t1") is False
        assert rbac.allowed_tenants("admin", "t2", "t1") is True

    def test_secret_manager_priority_env_over_file(self, monkeypatch, tmp_path):
        monkeypatch.setenv("PI_SECRET_JWT", "env_value")
        secret_file = tmp_path / "jwt"
        secret_file.write_text("file_value")
        sm = SecretManager(str(tmp_path))
        # Env takes priority
        assert sm.get("jwt") == "env_value"

    def test_metrics_counter_reset(self):
        m = MetricsRegistry()
        m.counter("c", ["l"], {"l": "v"}, 5)
        m.reset_counter("c")
        output = m.prometheus_format()
        assert 'c{l="v"} 5' not in output

    def test_security_context_immutable_fields(self):
        ctx = SecurityContext("t1", "actor_1", "operator", "corr_1")
        assert ctx.tenant_id == "t1"
        assert ctx.role == "operator"
        d = ctx.to_dict()
        assert d["correlation_id"] == "corr_1"
