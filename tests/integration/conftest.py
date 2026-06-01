"""Pytest configuration and shared fixtures for PI Platform integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from pi_agent_chain.ledger import StateLedger
from pi_extension_governor.manifest import CapabilityClass, TrustZone
from pi_interoperability_layer.platform.tenant import ResourceQuota, Tenant, TenantRegistry, TenantStatus, TenantTier


@pytest.fixture
def tenant_workspace_dir(tmp_path: Path) -> Path:
    """Fixture that creates and returns a clean tenant-isolated temporary workspace directory."""
    workspace = tmp_path / "workspaces"
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


@pytest.fixture
def tenant_registry(tenant_workspace_dir: Path) -> TenantRegistry:
    """Fixture that returns a populated TenantRegistry situated inside the tenant workspace."""
    registry_path = tenant_workspace_dir / "tenant_registry"
    registry = TenantRegistry(root_dir=registry_path)

    # Define Tenant A
    tenant_a = Tenant(
        tenant_id="tenant_A",
        tenant_name="Sovereign Compliance Corp",
        tier=TenantTier.ENTERPRISE,
        status=TenantStatus.ACTIVE,
        quota=ResourceQuota(
            max_capabilities=50,
            max_executions_per_hour=500,
            max_storage_mb=512,
            max_graph_nodes=200,
        ),
        trust_zones={TrustZone.CORE_TRUSTED, TrustZone.GOVERNED_EXTENSION},
        allowed_capability_classes={CapabilityClass.OPENAPI_TOOLING, CapabilityClass.STATIC_ANALYZER},
    )

    # Define Tenant B
    tenant_b = Tenant(
        tenant_id="tenant_B",
        tenant_name="Adversarial Audit Group",
        tier=TenantTier.STANDARD,
        status=TenantStatus.ACTIVE,
        quota=ResourceQuota(
            max_capabilities=20,
            max_executions_per_hour=100,
            max_storage_mb=128,
            max_graph_nodes=50,
        ),
        trust_zones={TrustZone.CORE_TRUSTED},
        allowed_capability_classes={CapabilityClass.OPENAPI_TOOLING},
    )

    success_a, err_a = registry.register(tenant_a)
    assert success_a, f"Failed to register Tenant A: {err_a}"

    success_b, err_b = registry.register(tenant_b)
    assert success_b, f"Failed to register Tenant B: {err_b}"

    return registry


@pytest.fixture
def tenant_a(tenant_registry: TenantRegistry) -> Tenant:
    """Fixture that returns Tenant A's loaded Immutable tenant model."""
    entry = tenant_registry.get("tenant_A")
    assert entry is not None
    return entry.tenant


@pytest.fixture
def tenant_b(tenant_registry: TenantRegistry) -> Tenant:
    """Fixture that returns Tenant B's loaded Immutable tenant model."""
    entry = tenant_registry.get("tenant_B")
    assert entry is not None
    return entry.tenant


@pytest.fixture
def state_ledger() -> StateLedger:
    """Fixture that returns an isolated in-memory StateLedger for execution trace audits."""
    return StateLedger(":memory:")
