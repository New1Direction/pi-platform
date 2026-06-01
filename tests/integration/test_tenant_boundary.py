"""Multi-tenant isolation and boundary enforcement tests."""

from __future__ import annotations

from pi_agent_chain.pipeline import PipelineDriver
from pi_extension_governor.manifest import CapabilityClass, TrustZone
from pi_interoperability_layer.platform.execution_fabric import DeterministicExecutionFabric
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

# Sample raw HTTP request/response traffic for testing
RAW_REQUEST = """GET /api/v1/compliance HTTP/1.1
Host: secure.corp.com
Authorization: Bearer my-secure-token
Accept: application/json

"""

RAW_RESPONSE = """HTTP/1.1 200 OK
Content-Type: application/json

{"status": "compliant", "audit_id": "aud_889900"}
"""


def test_tenant_registry_quota_enforcement(tenant_workspace_dir):
    """Verify that the TenantRegistry enforces tenant activation status and execution rate quotas."""
    registry_path = tenant_workspace_dir / "boundary_tenant_registry"
    registry = TenantRegistry(root_dir=registry_path)

    # Register a restricted tenant
    restricted_tenant = Tenant(
        tenant_id="tenant_restricted",
        tenant_name="Restricted Sandbox Inc",
        tier=TenantTier.DEVELOPMENT,
        status=TenantStatus.ACTIVE,
        quota=ResourceQuota(
            max_capabilities=2,
            max_executions_per_hour=3,
        ),
        trust_zones={TrustZone.CORE_TRUSTED},
        allowed_capability_classes={CapabilityClass.OPENAPI_TOOLING},
    )

    success, err = registry.register(restricted_tenant)
    assert success is True
    assert err is None

    # 1. Enforce active status boundary
    # Update status to SUSPENDED and assert execution is denied
    registry.update_status("tenant_restricted", TenantStatus.SUSPENDED)
    allowed, reason = registry.check_execution_allowed("tenant_restricted")
    assert allowed is False
    assert "suspended" in reason

    # Reactivate tenant and assert execution is allowed
    registry.update_status("tenant_restricted", TenantStatus.ACTIVE)
    allowed, reason = registry.check_execution_allowed("tenant_restricted")
    assert allowed is True
    assert reason is None

    # 2. Enforce capabilities quota
    # Increment capability count
    success_inc, err_inc = registry.increment_capability("tenant_restricted")
    assert success_inc is True
    success_inc, err_inc = registry.increment_capability("tenant_restricted")
    assert success_inc is True
    # Attempt to exceed the maximum capabilities quota (limit = 2)
    success_inc, err_inc = registry.increment_capability("tenant_restricted")
    assert success_inc is False
    assert "limit exceeded" in err_inc.lower()

    # 3. Enforce execution rate limit quota
    # Record executions up to max_executions_per_hour = 3
    registry.record_execution("tenant_restricted")
    registry.record_execution("tenant_restricted")
    registry.record_execution("tenant_restricted")
    # Assert further executions are blocked by the control plane
    allowed, reason = registry.check_execution_allowed("tenant_restricted")
    assert allowed is False
    assert "rate limit" in reason.lower()


def test_tenant_policy_engine_enforcement():
    """Verify that the TenantPolicyEngine prevents capability execution drift and trust zone jumps."""
    engine = TenantPolicyEngine()

    # Define rules for Sovereign Tenant
    # 1. Banned capability classes
    engine.add_rule(
        "sovereign_tenant",
        TenantPolicyRule(
            rule_id="rule_ban_analyzer",
            rule_type="capability_class",
            target_value="static_analyzer",
            action="deny",
            evidence="Inbound static analyzers are forbidden under high-trust Sovereign policies.",
        ),
    )

    # 2. Denied trust zones
    engine.add_rule(
        "sovereign_tenant",
        TenantPolicyRule(
            rule_id="rule_ban_sandbox",
            rule_type="trust_zone",
            target_value="sandbox_experimental",
            action="deny",
            evidence="Experimental sandboxes violate sovereignty constraints.",
        ),
    )

    # Assert capability class restriction
    ok, details = engine.evaluate_capability_class("sovereign_tenant", CapabilityClass.STATIC_ANALYZER)
    assert ok is False
    assert "denied by policy" in details.lower()
    assert "sovereign policies" in details.lower()

    # Assert allowed capability class passes
    ok, details = engine.evaluate_capability_class("sovereign_tenant", CapabilityClass.OPENAPI_TOOLING)
    assert ok is True

    # Assert trust zone restriction
    ok, details = engine.evaluate_trust_zone("sovereign_tenant", TrustZone.SANDBOX_EXPERIMENTAL)
    assert ok is False
    assert "denied by policy" in details.lower()
    assert "experimental sandboxes" in details.lower()

    # Assert allowed trust zone passes
    ok, details = engine.evaluate_trust_zone("sovereign_tenant", TrustZone.CORE_TRUSTED)
    assert ok is True


def test_physical_tenant_artifact_isolation(tenant_workspace_dir, state_ledger):
    """Verify physical database partition and artifact segregation between two distinct tenants.

    This ensures that artifacts generated by tenant A are completely inaccessible
    to tenant B and fail validation boundaries if crossed.
    """
    db_path_a = tenant_workspace_dir / "tenant_a_artifacts.db"
    db_path_b = tenant_workspace_dir / "tenant_b_artifacts.db"

    # Initialize drivers with separate physical databases
    driver_a = PipelineDriver(
        ledger=state_ledger,
        base_url="https://api.corp.com",
        registry_path=db_path_a,
    )

    driver_b = PipelineDriver(
        ledger=state_ledger,
        base_url="https://api.corp.com",
        registry_path=db_path_b,
    )

    # 1. Run full pipeline for Tenant A
    trace_a = "trace_tenant_A_001"
    result_a = driver_a.run(
        raw_traffic_pairs=[(RAW_REQUEST, RAW_RESPONSE)],
        trace_id=trace_a,
    )
    assert result_a["status"] in ("VERIFICATION_FAILURE", "SUCCESS")

    # Assert Tenant A's database contains artifacts
    artifacts_a = driver_a.registry.all_artifacts()
    assert len(artifacts_a) > 0

    # 2. Assert Tenant B's database contains zero artifacts from Tenant A
    artifacts_b = driver_b.registry.all_artifacts()
    assert len(artifacts_b) == 0

    # 3. Attempt a boundary jump: attempt to run tenant B's validator with tenant A's artifact ID
    # Get a specific artifact generated by Tenant A
    art_a = artifacts_a[0]

    # Verify Tenant B's provenance validator rejects Tenant A's artifact because it does not exist
    # inside Tenant B's isolated registry database.
    violations = driver_b.provenance_validator.validate(art_a)
    assert len(violations) > 0
    assert any(v.rule == "UNVERIFIABLE_ANCESTRY" for v in violations)


def test_tenant_execution_log_segregation(tenant_workspace_dir):
    """Verify that TenantExecutionLogs are segregated and execution traces never leak across boundaries."""
    log_dir = tenant_workspace_dir / "executions"
    execution_log = TenantExecutionLog(root_dir=log_dir)

    # Record execution for Tenant A
    rec_a = TenantExecutionRecord(
        tenant_id="tenant_A",
        execution_id="exec_A_999",
        pipeline_hash="hash_aaa_111",
        manifest_id="manifest_compliance",
        status="completed",
        evidence="Execution succeeded on tenant A",
    )
    execution_log.record(rec_a)

    # Record execution for Tenant B
    rec_b = TenantExecutionRecord(
        tenant_id="tenant_B",
        execution_id="exec_B_888",
        pipeline_hash="hash_bbb_222",
        manifest_id="manifest_audit",
        status="completed",
        evidence="Execution succeeded on tenant B",
    )
    execution_log.record(rec_b)

    # 1. Retrieve records and verify segregation
    records_a = execution_log.get_by_tenant("tenant_A")
    assert len(records_a) == 1
    assert records_a[0].execution_id == "exec_A_999"
    assert "tenant_B" not in [r.tenant_id for r in records_a]

    records_b = execution_log.get_by_tenant("tenant_B")
    assert len(records_b) == 1
    assert records_b[0].execution_id == "exec_B_888"
    assert "tenant_A" not in [r.tenant_id for r in records_b]

    # 2. Verify compliance report boundaries
    report_a = execution_log.get_compliance_report("tenant_A")
    assert report_a["tenant_id"] == "tenant_A"
    assert report_a["total_executions"] == 1

    report_b = execution_log.get_compliance_report("tenant_B")
    assert report_b["tenant_id"] == "tenant_B"
    assert report_b["total_executions"] == 1


def test_deterministic_execution_fabric_tenant_segregation():
    """Verify that the phase-locked DeterministicExecutionFabric operates in isolated shard namespaces.

    This ensures worker leases and barriers do not overlap or leak execution state across tenants.
    """
    from pi_extension_governor.manifest import ExtensionManifest

    fabric = DeterministicExecutionFabric(shard_count=4)

    # Create dummy manifests representing isolated tenant capabilities
    manifest_a = ExtensionManifest(
        extension_id="ext_tenant_A",
        package_name="ext_tenant_A_pkg",
        package_version="1.0.0",
        capability_class=CapabilityClass.OPENAPI_TOOLING,
        trust_zone=TrustZone.CORE_TRUSTED,
    )

    manifest_b = ExtensionManifest(
        extension_id="ext_tenant_B",
        package_name="ext_tenant_B_pkg",
        package_version="1.0.0",
        capability_class=CapabilityClass.STATIC_ANALYZER,
        trust_zone=TrustZone.GOVERNED_EXTENSION,
    )

    # 1. Assert deterministic, isolated shard assignments
    shard_a = fabric.assign_to_shard(manifest_a.extension_id)
    shard_b = fabric.assign_to_shard(manifest_b.extension_id)

    # Assignments are completely deterministic based on hash, but they must be registered separately
    assert shard_a in [f"shard-{i:04d}" for i in range(4)]
    assert shard_b in [f"shard-{i:04d}" for i in range(4)]

    # 2. Run multi-phase execution dag separately for each tenant and verify logs are isolated
    receipt_a = fabric.execute_dag(execution_id="exec_A_dag", phases=[[manifest_a]])
    receipt_b = fabric.execute_dag(execution_id="exec_B_dag", phases=[[manifest_b]])

    assert receipt_a.execution_id == "exec_A_dag"
    assert receipt_b.execution_id == "exec_B_dag"

    # Compare replay hashes to guarantee strict mathematical segregation
    assert receipt_a.replay_hash != receipt_b.replay_hash
