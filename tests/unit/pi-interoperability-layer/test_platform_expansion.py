"""Tests for the 3-Layer Platform Expansion.

Layer 1: Multi-Tenant SaaS Control Plane
Layer 2: Shard-Coordinated Deterministic Execution Fabric
Layer 3: Capability Economy (Marketplace + Composition Engine)

All tests enforce deterministic, fail-closed, evidence-bound behavior.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pi_extension_governor.manifest import (
    CapabilityClass,
    ExtensionManifest,
    TrustZone,
)
from pi_interoperability_layer.platform.execution_fabric import (
    DeterministicExecutionFabric,
    ExecutionAuditLog,
)
from pi_interoperability_layer.platform.marketplace import (
    CapabilityLifecycleState,
    CapabilityMarketplaceRegistry,
    CompositionEdge,
    CompositionEngine,
    CompositionNode,
    CompositionRequest,
    MarketCapabilityListing,
    TrustTier,
)
from pi_interoperability_layer.platform.tenant import (
    ResourceQuota,
    Tenant,
    TenantExecutionLog,
    TenantExecutionRecord,
    TenantPolicyEngine,
    TenantPolicyRule,
    TenantRegistry,
    TenantStatus,
    TenantTier,
)

# ── Layer 1: Tenant Control Plane Tests ──────────────────────────────


class TestTenantRegistry:
    def test_register_tenant(self, tmp_path: Path) -> None:
        reg = TenantRegistry(root_dir=tmp_path)
        tenant = Tenant(tenant_id="t1", tenant_name="Test Corp", tier=TenantTier.ENTERPRISE)
        ok, err = reg.register(tenant)
        assert ok is True
        assert err is None
        assert reg.get("t1").tenant.compute_hash() == tenant.compute_hash()

    def test_register_duplicate_fails(self, tmp_path: Path) -> None:
        reg = TenantRegistry(root_dir=tmp_path)
        tenant = Tenant(tenant_id="t1", tenant_name="Test Corp")
        reg.register(tenant)
        ok, err = reg.register(tenant)
        assert ok is False
        assert "already exists" in err

    def test_tenant_quota_enforcement(self, tmp_path: Path) -> None:
        reg = TenantRegistry(root_dir=tmp_path)
        quota = ResourceQuota(max_capabilities=2)
        tenant = Tenant(tenant_id="t1", tenant_name="Test", quota=quota)
        reg.register(tenant)
        assert reg.increment_capability("t1")[0] is True
        assert reg.increment_capability("t1")[0] is True
        assert reg.increment_capability("t1")[0] is False

    def test_execution_rate_limit(self, tmp_path: Path) -> None:
        reg = TenantRegistry(root_dir=tmp_path)
        quota = ResourceQuota(max_executions_per_hour=2)
        tenant = Tenant(tenant_id="t1", tenant_name="Test", quota=quota, status=TenantStatus.ACTIVE)
        reg.register(tenant)
        assert reg.check_execution_allowed("t1")[0] is True
        reg.record_execution("t1")
        assert reg.check_execution_allowed("t1")[0] is True
        reg.record_execution("t1")
        assert reg.check_execution_allowed("t1")[0] is False

    def test_audit_logging(self, tmp_path: Path) -> None:
        reg = TenantRegistry(root_dir=tmp_path)
        tenant = Tenant(tenant_id="t1", tenant_name="Test")
        reg.register(tenant)
        reg.increment_capability("t1")
        log = reg.get_audit_log("t1")
        assert len(log) >= 2
        assert log[-1]["tenant_id"] == "t1"

    def test_tenant_hash_determinism(self) -> None:
        t1 = Tenant(tenant_id="t1", tenant_name="Test", tier=TenantTier.STANDARD)
        t2 = Tenant(tenant_id="t1", tenant_name="Test", tier=TenantTier.STANDARD)
        assert t1.compute_hash() == t2.compute_hash()

    def test_tenant_hash_changes_on_mutation(self) -> None:
        t1 = Tenant(tenant_id="t1", tenant_name="Test", status=TenantStatus.ACTIVE)
        t2 = Tenant(tenant_id="t1", tenant_name="Test", status=TenantStatus.SUSPENDED)
        assert t1.compute_hash() != t2.compute_hash()


class TestTenantPolicyEngine:
    def test_capability_class_allow(self) -> None:
        engine = TenantPolicyEngine()
        engine.add_rule("t1", TenantPolicyRule("r1", "capability_class", "openapi_tooling", "allow"))
        ok, evidence = engine.evaluate_capability_class("t1", CapabilityClass.OPENAPI_TOOLING)
        assert ok is True
        assert evidence == "OK"

    def test_capability_class_deny_overrides(self) -> None:
        engine = TenantPolicyEngine()
        engine.add_rule("t1", TenantPolicyRule("r1", "capability_class", "openapi_tooling", "allow"))
        engine.add_rule("t1", TenantPolicyRule("r2", "capability_class", "openapi_tooling", "deny", "security_review"))
        ok, evidence = engine.evaluate_capability_class("t1", CapabilityClass.OPENAPI_TOOLING)
        assert ok is False
        assert "denied" in evidence

    def test_trust_zone_deny(self) -> None:
        engine = TenantPolicyEngine()
        engine.add_rule("t1", TenantPolicyRule("r1", "trust_zone", "sandbox_experimental", "deny"))
        ok, evidence = engine.evaluate_trust_zone("t1", TrustZone.SANDBOX_EXPERIMENTAL)
        assert ok is False
        assert "denied" in evidence

    def test_empty_policy_allows_all(self) -> None:
        engine = TenantPolicyEngine()
        ok, _ = engine.evaluate_capability_class("t1", CapabilityClass.STATIC_ANALYZER)
        assert ok is True


class TestTenantExecutionLog:
    def test_record_and_retrieve(self, tmp_path: Path) -> None:
        log = TenantExecutionLog(root_dir=tmp_path)
        rec = TenantExecutionRecord(
            tenant_id="t1",
            execution_id="e1",
            pipeline_hash="abc123",
            manifest_id="m1",
            status="completed",
            evidence="success",
        )
        log.record(rec)
        found = log.get_by_tenant("t1")
        assert len(found) == 1
        assert found[0].execution_id == "e1"

    def test_compliance_report(self, tmp_path: Path) -> None:
        log = TenantExecutionLog(root_dir=tmp_path)
        for i, status in enumerate(["completed", "completed", "failed", "rejected"]):
            log.record(
                TenantExecutionRecord(
                    tenant_id="t1",
                    execution_id=f"e{i}",
                    pipeline_hash="h",
                    manifest_id="m",
                    status=status,
                )
            )
        report = log.get_compliance_report("t1")
        assert report["total_executions"] == 4
        assert report["completed"] == 2
        assert report["failed"] == 1
        assert report["rejected"] == 1
        assert report["success_rate"] == 0.5

    def test_replay_candidates(self, tmp_path: Path) -> None:
        log = TenantExecutionLog(root_dir=tmp_path)
        log.record(TenantExecutionRecord("t1", "e1", "hashA", "m1", "completed"))
        log.record(TenantExecutionRecord("t1", "e2", "hashA", "m1", "completed"))
        log.record(TenantExecutionRecord("t1", "e3", "hashB", "m1", "completed"))
        candidates = log.get_replay_candidates("t1", "hashA")
        assert len(candidates) == 2


# ── Layer 2: Execution Fabric Tests ─────────────────────────────────


class TestDeterministicShardAssignment:
    def test_same_manifest_same_shard(self) -> None:
        fabric = DeterministicExecutionFabric(shard_count=4)
        s1 = fabric.assign_to_shard("manifest_a")
        s2 = fabric.assign_to_shard("manifest_a")
        assert s1 == s2

    def test_different_manifests_different_shards(self) -> None:
        fabric = DeterministicExecutionFabric(shard_count=4)
        fabric.assign_to_shard("manifest_a")
        fabric.assign_to_shard("manifest_b")
        # Not guaranteed different, but highly likely
        assignments = {fabric.assign_to_shard(f"manifest_{i}") for i in range(1000)}
        assert len(assignments) == 4  # uses all shards

    def test_shard_assignments_recorded(self) -> None:
        fabric = DeterministicExecutionFabric(shard_count=2)
        fabric.assign_to_shard("m1")
        assert "m1" in fabric.get_shard_assignments("shard-0000") or "m1" in fabric.get_shard_assignments("shard-0001")


class TestWorkerLeasing:
    def test_lease_created(self) -> None:
        fabric = DeterministicExecutionFabric()
        lease = fabric.lease_worker("shard-0000", "m1", phase_number=1)
        assert lease.shard_id == "shard-0000"
        assert lease.manifest_id == "m1"
        assert lease.phase_number == 1
        assert lease.compute_hash() != ""

    def test_lease_released(self) -> None:
        fabric = DeterministicExecutionFabric()
        lease = fabric.lease_worker("shard-0000", "m1", phase_number=1)
        released = fabric.release_lease(lease.lease_id)
        assert released == lease
        assert fabric.release_lease(lease.lease_id) is None


class TestPhaseExecution:
    @pytest.fixture
    def sample_manifests(self) -> list:
        return [
            ExtensionManifest(
                extension_id="m1",
                package_name="pkg1",
                package_version="1.0.0",
                package_hash="",
                capability_class=CapabilityClass.OPENAPI_TOOLING,
            ),
            ExtensionManifest(
                extension_id="m2",
                package_name="pkg2",
                package_version="1.0.0",
                package_hash="",
                capability_class=CapabilityClass.STATIC_ANALYZER,
            ),
        ]

    def test_phase_execution_completes(self, sample_manifests: list) -> None:
        fabric = DeterministicExecutionFabric(shard_count=2)
        receipt = fabric.execute_phase(1, sample_manifests)
        assert receipt.final_status == "success"
        assert receipt.phases_completed == 2
        assert receipt.phases_failed == 0
        assert receipt.replay_hash != ""

    def test_phase_receipts_stored(self, sample_manifests: list) -> None:
        fabric = DeterministicExecutionFabric(shard_count=2)
        fabric.execute_phase(1, sample_manifests)
        assert 1 in fabric._phase_receipts
        assert len(fabric._phase_receipts[1]) == 2

    def test_barrier_created(self, sample_manifests: list) -> None:
        fabric = DeterministicExecutionFabric(shard_count=2)
        fabric.execute_phase(1, sample_manifests)
        assert 1 in fabric._barriers
        barrier = fabric._barriers[1]
        assert barrier.barrier_status == "closed"
        assert barrier.all_complete() is True


class TestMultiPhaseExecution:
    @pytest.fixture
    def two_phase_manifests(self) -> list:
        return [
            [
                ExtensionManifest(
                    extension_id="m1",
                    package_name="pkg1",
                    package_version="1.0.0",
                    package_hash="",
                    capability_class=CapabilityClass.OPENAPI_TOOLING,
                ),
            ],
            [
                ExtensionManifest(
                    extension_id="m2",
                    package_name="pkg2",
                    package_version="1.0.0",
                    package_hash="",
                    capability_class=CapabilityClass.STATIC_ANALYZER,
                ),
            ],
        ]

    def test_dag_execution_success(self, two_phase_manifests: list) -> None:
        fabric = DeterministicExecutionFabric(shard_count=2)
        receipt = fabric.execute_dag("exec_1", two_phase_manifests)
        assert receipt.final_status == "success"
        assert receipt.total_phases == 2
        assert len(receipt.phase_receipts) == 2
        assert receipt.replay_hash != ""

    def test_dag_replay_hash_determinism(self, two_phase_manifests: list) -> None:
        fabric = DeterministicExecutionFabric(shard_count=2)
        receipt1 = fabric.execute_dag("exec_1", two_phase_manifests)
        receipt2 = fabric.execute_dag("exec_2", two_phase_manifests)
        # Same inputs should produce same replay hash (deterministic)
        assert receipt1.replay_hash == receipt2.replay_hash


class TestExecutionAuditLog:
    def test_log_and_retrieve(self) -> None:
        log = ExecutionAuditLog()
        log.log("exec_1", "START", "Phase 1 started")
        log.log("exec_1", "COMPLETE", "Phase 1 completed", "hash123")
        events = log.get_events("exec_1")
        assert len(events) == 2
        assert events[0]["event_type"] == "START"
        assert events[1]["evidence_hash"] == "hash123"


# ── Layer 3: Capability Economy Tests ────────────────────────────────


class TestCompositionRequest:
    def test_request_hash_determinism(self) -> None:
        req1 = CompositionRequest(
            request_id="r1",
            tenant_id="t1",
            description="test",
            nodes=[
                CompositionNode(node_id="n1", manifest_id="m1", capability_class=CapabilityClass.OPENAPI_TOOLING),
            ],
            edges=[],
        )
        req2 = CompositionRequest(
            request_id="r1",
            tenant_id="t1",
            description="test",
            nodes=[
                CompositionNode(node_id="n1", manifest_id="m1", capability_class=CapabilityClass.OPENAPI_TOOLING),
            ],
            edges=[],
        )
        assert req1.compute_hash() == req2.compute_hash()

    def test_request_hash_changes_on_modification(self) -> None:
        req1 = CompositionRequest(request_id="r1", tenant_id="t1", description="test", nodes=[], edges=[])
        req2 = CompositionRequest(request_id="r1", tenant_id="t1", description="different", nodes=[], edges=[])
        assert req1.compute_hash() != req2.compute_hash()


class TestCompositionEngine:
    @pytest.fixture
    def engine_with_catalog(self) -> CompositionEngine:
        engine = CompositionEngine()
        engine.register_listing(
            MarketCapabilityListing(
                listing_id="l1",
                manifest_id="m1",
                name="openapi-tool",
                version="1.0.0",
                capability_class=CapabilityClass.OPENAPI_TOOLING,
                trust_tier=TrustTier.VERIFIED,
                trust_score=75,
                publisher_tenant_id="t1",
            )
        )
        engine.register_listing(
            MarketCapabilityListing(
                listing_id="l2",
                manifest_id="m2",
                name="static-analyzer",
                version="1.0.0",
                capability_class=CapabilityClass.STATIC_ANALYZER,
                trust_tier=TrustTier.VERIFIED,
                trust_score=80,
                publisher_tenant_id="t1",
            )
        )
        return engine

    def test_compose_valid_request(self, engine_with_catalog: CompositionEngine) -> None:
        req = CompositionRequest(
            request_id="r1",
            tenant_id="t1",
            description="test",
            nodes=[
                CompositionNode(node_id="n1", manifest_id="m1", capability_class=CapabilityClass.OPENAPI_TOOLING),
            ],
            edges=[],
        )
        result = engine_with_catalog.compose(req)
        assert result.valid is True
        assert len(result.resolved_manifests) == 1
        assert result.composition_hash != ""
        assert result.phase_count == 1

    def test_compose_missing_node(self, engine_with_catalog: CompositionEngine) -> None:
        req = CompositionRequest(
            request_id="r1",
            tenant_id="t1",
            description="test",
            nodes=[
                CompositionNode(node_id="n1", manifest_id="missing", capability_class=CapabilityClass.OPENAPI_TOOLING),
            ],
            edges=[],
        )
        result = engine_with_catalog.compose(req)
        assert result.valid is False
        assert "not found in catalog" in result.rejection_reason

    def test_compose_trust_tier_rejection(self, engine_with_catalog: CompositionEngine) -> None:
        req = CompositionRequest(
            request_id="r1",
            tenant_id="t1",
            description="test",
            nodes=[
                CompositionNode(
                    node_id="n1",
                    manifest_id="m1",
                    capability_class=CapabilityClass.OPENAPI_TOOLING,
                    trust_tier_minimum=TrustTier.CORE,
                ),
            ],
            edges=[],
        )
        result = engine_with_catalog.compose(req)
        assert result.valid is False
        assert "Trust tier mismatch" in result.rejection_reason

    def test_compose_max_nodes_enforcement(self, engine_with_catalog: CompositionEngine) -> None:
        req = CompositionRequest(
            request_id="r1",
            tenant_id="t1",
            description="test",
            nodes=[
                CompositionNode(node_id="n1", manifest_id="m1", capability_class=CapabilityClass.OPENAPI_TOOLING),
                CompositionNode(node_id="n2", manifest_id="m2", capability_class=CapabilityClass.STATIC_ANALYZER),
            ],
            edges=[],
            max_nodes=1,
        )
        result = engine_with_catalog.compose(req)
        assert result.valid is False
        assert "max_nodes 1" in result.rejection_reason

    def test_compose_with_edges(self, engine_with_catalog: CompositionEngine) -> None:
        req = CompositionRequest(
            request_id="r1",
            tenant_id="t1",
            description="test",
            nodes=[
                CompositionNode(node_id="n1", manifest_id="m1", capability_class=CapabilityClass.OPENAPI_TOOLING),
                CompositionNode(node_id="n2", manifest_id="m2", capability_class=CapabilityClass.STATIC_ANALYZER),
            ],
            edges=[
                CompositionEdge(source_node_id="n1", target_node_id="n2", edge_type="depends_on"),
            ],
        )
        result = engine_with_catalog.compose(req)
        assert result.valid is True
        assert len(result.resolved_edges) == 1
        assert result.phase_count == 2

    def test_composition_result_hash_determinism(self, engine_with_catalog: CompositionEngine) -> None:
        req = CompositionRequest(
            request_id="r1",
            tenant_id="t1",
            description="test",
            nodes=[
                CompositionNode(node_id="n1", manifest_id="m1", capability_class=CapabilityClass.OPENAPI_TOOLING),
            ],
            edges=[],
        )
        result1 = engine_with_catalog.compose(req)
        result2 = engine_with_catalog.compose(req)
        assert result1.composition_hash == result2.composition_hash

    def test_composition_history_logged(self, engine_with_catalog: CompositionEngine) -> None:
        req = CompositionRequest(
            request_id="r1",
            tenant_id="t1",
            description="test",
            nodes=[
                CompositionNode(node_id="n1", manifest_id="m1", capability_class=CapabilityClass.OPENAPI_TOOLING),
            ],
            edges=[],
        )
        engine_with_catalog.compose(req)
        assert len(engine_with_catalog.composition_history) == 1


class TestCapabilityMarketplaceLifecycle:
    def test_publish_and_retrieve(self) -> None:
        registry = CapabilityMarketplaceRegistry()
        listing = MarketCapabilityListing(
            listing_id="l1",
            manifest_id="m1",
            name="tool",
            version="1.0.0",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            trust_tier=TrustTier.BASIC,
            publisher_tenant_id="t1",
        )
        registry.publish(listing)
        found = registry.get_listing("l1")
        assert found is not None
        assert found.lifecycle_state == CapabilityLifecycleState.PUBLISHED

    def test_lifecycle_transition(self) -> None:
        registry = CapabilityMarketplaceRegistry()
        listing = MarketCapabilityListing(
            listing_id="l1",
            manifest_id="m1",
            name="tool",
            version="1.0.0",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            trust_tier=TrustTier.BASIC,
            publisher_tenant_id="t1",
        )
        registry.publish(listing)
        ok = registry.transition_state("l1", CapabilityLifecycleState.VERIFIED, evidence_hash="hash123")
        assert ok is True
        assert registry.get_listing("l1").lifecycle_state == CapabilityLifecycleState.VERIFIED

    def test_deprecation(self) -> None:
        registry = CapabilityMarketplaceRegistry()
        listing = MarketCapabilityListing(
            listing_id="l1",
            manifest_id="m1",
            name="tool",
            version="1.0.0",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            trust_tier=TrustTier.BASIC,
            publisher_tenant_id="t1",
        )
        registry.publish(listing)
        registry.transition_state("l1", CapabilityLifecycleState.DEPRECATED, reason="replaced by v2")
        found = registry.get_listing("l1")
        assert found.lifecycle_state == CapabilityLifecycleState.DEPRECATED
        assert found.deprecation_reason == "replaced by v2"

    def test_trust_score_update(self) -> None:
        registry = CapabilityMarketplaceRegistry()
        listing = MarketCapabilityListing(
            listing_id="l1",
            manifest_id="m1",
            name="tool",
            version="1.0.0",
            capability_class=CapabilityClass.OPENAPI_TOOLING,
            trust_tier=TrustTier.BASIC,
            trust_score=10,
            publisher_tenant_id="t1",
        )
        registry.publish(listing)
        ok = registry.update_trust_score("l1", 95, evidence="determinism_verified")
        assert ok is True
        assert registry.get_listing("l1").trust_score == 95

    def test_query_by_class(self) -> None:
        registry = CapabilityMarketplaceRegistry()
        registry.publish(
            MarketCapabilityListing(
                "l1", "m1", "tool1", "1.0", CapabilityClass.OPENAPI_TOOLING, TrustTier.BASIC, publisher_tenant_id="t1"
            )
        )
        registry.publish(
            MarketCapabilityListing(
                "l2", "m2", "tool2", "1.0", CapabilityClass.STATIC_ANALYZER, TrustTier.BASIC, publisher_tenant_id="t1"
            )
        )
        openapi_listings = registry.query_by_class(CapabilityClass.OPENAPI_TOOLING)
        assert len(openapi_listings) == 1
        assert openapi_listings[0].listing_id == "l1"

    def test_query_by_tier(self) -> None:
        registry = CapabilityMarketplaceRegistry()
        registry.publish(
            MarketCapabilityListing(
                "l1", "m1", "tool1", "1.0", CapabilityClass.OPENAPI_TOOLING, TrustTier.BASIC, publisher_tenant_id="t1"
            )
        )
        registry.publish(
            MarketCapabilityListing(
                "l2",
                "m2",
                "tool2",
                "1.0",
                CapabilityClass.STATIC_ANALYZER,
                TrustTier.CERTIFIED,
                publisher_tenant_id="t1",
            )
        )
        basic_listings = registry.query_by_tier(TrustTier.BASIC)
        assert len(basic_listings) == 1
        assert basic_listings[0].listing_id == "l1"

    def test_listing_hash_determinism(self) -> None:
        l1 = MarketCapabilityListing(
            "l1", "m1", "tool", "1.0", CapabilityClass.OPENAPI_TOOLING, TrustTier.BASIC, publisher_tenant_id="t1"
        )
        l2 = MarketCapabilityListing(
            "l1", "m1", "tool", "1.0", CapabilityClass.OPENAPI_TOOLING, TrustTier.BASIC, publisher_tenant_id="t1"
        )
        assert l1.compute_hash() == l2.compute_hash()


# ── Cross-Layer Integration Tests ────────────────────────────────────


class TestCrossLayerIntegration:
    def test_tenant_runs_composition_through_fabric(self, tmp_path: Path) -> None:
        """End-to-end: Tenant → Composition → Execution Fabric."""
        # Layer 1: Register tenant
        tenant_reg = TenantRegistry(root_dir=tmp_path)
        tenant = Tenant(tenant_id="t1", tenant_name="Corp", tier=TenantTier.ENTERPRISE, status=TenantStatus.ACTIVE)
        tenant_reg.register(tenant)

        # Layer 3: Build composition
        marketplace = CapabilityMarketplaceRegistry()
        marketplace.publish(
            MarketCapabilityListing(
                listing_id="l1",
                manifest_id="m1",
                name="detector",
                version="1.0.0",
                capability_class=CapabilityClass.STATIC_ANALYZER,
                trust_tier=TrustTier.VERIFIED,
                trust_score=90,
                publisher_tenant_id="t1",
            )
        )

        engine = CompositionEngine({"l1": marketplace.get_listing("l1")})
        request = CompositionRequest(
            request_id="req1",
            tenant_id="t1",
            description="security scan",
            nodes=[CompositionNode(node_id="n1", manifest_id="m1", capability_class=CapabilityClass.STATIC_ANALYZER)],
            edges=[],
        )
        composition = engine.compose(request)
        assert composition.valid is True

        # Layer 1: Check tenant can execute
        ok, err = tenant_reg.check_execution_allowed("t1")
        assert ok is True

        # Layer 2: Execute through fabric
        fabric = DeterministicExecutionFabric(shard_count=2)
        manifests = list(composition.resolved_manifests)
        receipt = fabric.execute_phase(1, manifests)
        assert receipt.final_status == "success"

        # Layer 1: Record execution
        tenant_reg.record_execution("t1")
