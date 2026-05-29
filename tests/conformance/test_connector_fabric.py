"""Connector Fabric Conformance Tests.

Tests covering:
- Connector SDK (manifest, receipt, normalizer, base worker)
- Canonical Normalization Engine (all 7 artifact families)
- 7 Governed Connectors (K8s, Terraform, OTel, AWS IAM, GitHub Actions, Docker, PostgreSQL)
- Connector Marketplace + Governance
- Cross-System Topology Engine
- Digital Twin Import + Replay Pipeline

All deterministic. Zero randomness.
"""

from __future__ import annotations

import os
import tempfile
import time

import pytest

from pi_connector_fabric.connectors.aws_iam.connector import AWSIAMConnector
from pi_connector_fabric.connectors.docker.connector import DockerConnector
from pi_connector_fabric.connectors.github_actions.connector import GitHubActionsConnector
from pi_connector_fabric.connectors.k8s.connector import KubernetesConnector
from pi_connector_fabric.connectors.opentelemetry.connector import OpenTelemetryConnector
from pi_connector_fabric.connectors.postgresql.connector import PostgreSQLConnector
from pi_connector_fabric.connectors.terraform.connector import TerraformStateConnector
from pi_connector_fabric.marketplace.governance import (
    ConnectorGovernance,
    ConnectorMarketplaceRegistry,
)
from pi_connector_fabric.replay.import_pipeline import DigitalTwinImport
from pi_connector_fabric.sdk.core import (
    ArtifactNormalizer,
    ConnectorCapabilityClass,
    ConnectorExecutionFence,
    ConnectorManifest,
    ConnectorSandboxPolicy,
    IngestionReceipt,
    NormalizedArtifact,
    register_connector,
)
from pi_connector_fabric.topology.engine import (
    CrossSystemDependencyGraph,
    RiskPropagationTopology,
    UnifiedTopologyGraph,
)
from pi_event_fabric.governance.compiler import (
    Condition,
    ConditionOperator,
    Effect,
    GovernanceEngine,
    GovernanceRule,
    PolicyCompiler,
)

# ──────────────────────────────
#  Fixtures
# ──────────────────────────────


@pytest.fixture
def marketplace():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    reg = ConnectorMarketplaceRegistry(path)
    yield reg
    os.unlink(path)


@pytest.fixture
def governance_engine():
    return GovernanceEngine()


@pytest.fixture
def k8s_connector():
    return KubernetesConnector(KubernetesConnector.MANIFEST, {})


@pytest.fixture
def terraform_connector():
    return TerraformStateConnector(TerraformStateConnector.MANIFEST, {})


@pytest.fixture
def otel_connector():
    return OpenTelemetryConnector(OpenTelemetryConnector.MANIFEST, {})


@pytest.fixture
def iam_connector():
    return AWSIAMConnector(AWSIAMConnector.MANIFEST, {})


@pytest.fixture
def gh_connector():
    return GitHubActionsConnector(GitHubActionsConnector.MANIFEST, {})


@pytest.fixture
def docker_connector():
    return DockerConnector(DockerConnector.MANIFEST, {})


@pytest.fixture
def pg_connector():
    return PostgreSQLConnector(PostgreSQLConnector.MANIFEST, {})


# ──────────────────────────────
#  Connector SDK Tests
# ──────────────────────────────


class TestConnectorSDK:
    def test_connector_manifest_hash(self):
        m = ConnectorManifest(
            connector_id="test.v1",
            name="Test",
            version="1.0.0",
            description="",
            capability_classes=(),
            sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
            target_systems=(),
            output_schemas=(),
            required_credentials=(),
            config_schema={},
        )
        assert m.manifest_hash != ""
        assert len(m.manifest_hash) == 64

    def test_connector_manifest_deterministic_hash(self):
        m1 = ConnectorManifest(
            connector_id="test.v1",
            name="Test",
            version="1.0.0",
            description="desc",
            capability_classes=(ConnectorCapabilityClass.TOPOLOGY_READ,),
            sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
            target_systems=("a",),
            output_schemas=("X",),
            required_credentials=(),
            config_schema={},
        )
        m2 = ConnectorManifest(
            connector_id="test.v1",
            name="Test",
            version="1.0.0",
            description="desc",
            capability_classes=(ConnectorCapabilityClass.TOPOLOGY_READ,),
            sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
            target_systems=("a",),
            output_schemas=("X",),
            required_credentials=(),
            config_schema={},
        )
        assert m1.manifest_hash == m2.manifest_hash

    def test_ingestion_receipt_hash(self):
        r = IngestionReceipt(
            receipt_id="r1",
            connector_id="c1",
            connector_version="1.0.0",
            tenant_id="t1",
            actor_id="a1",
            correlation_id="c1",
            ingestion_start="2026-01-01T00:00:00Z",
            ingestion_end="2026-01-01T00:00:01Z",
            artifact_count=2,
            artifact_hashes=("h1", "h2"),
            fence_used=ConnectorExecutionFence.SANDBOXED_READ,
            sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
            error_count=0,
            errors=(),
        )
        assert r.receipt_hash != ""
        assert r.verify() is True

    def test_ingestion_receipt_tampered_fails(self):
        r = IngestionReceipt(
            receipt_id="r1",
            connector_id="c1",
            connector_version="1.0.0",
            tenant_id="t1",
            actor_id="a1",
            correlation_id="c1",
            ingestion_start="2026-01-01T00:00:00Z",
            ingestion_end="2026-01-01T00:00:01Z",
            artifact_count=2,
            artifact_hashes=("h1", "h2"),
            fence_used=ConnectorExecutionFence.SANDBOXED_READ,
            sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
            error_count=0,
            errors=(),
        )
        # Tamper with artifact count
        tampered = IngestionReceipt(
            receipt_id="r1",
            connector_id="c1",
            connector_version="1.0.0",
            tenant_id="t1",
            actor_id="a1",
            correlation_id="c1",
            ingestion_start="2026-01-01T00:00:00Z",
            ingestion_end="2026-01-01T00:00:01Z",
            artifact_count=99,
            artifact_hashes=("h1", "h2"),
            fence_used=ConnectorExecutionFence.SANDBOXED_READ,
            sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
            error_count=0,
            errors=(),
            receipt_hash=r.receipt_hash,
        )
        assert tampered.verify() is False

    def test_normalized_artifact_hash(self):
        a = NormalizedArtifact(
            artifact_id="a1",
            artifact_family="X",
            artifact_schema_version="1.0.0",
            source_system="s1",
            connector_id="c1",
            connector_version="1.0.0",
            tenant_id="t1",
            correlation_id="c1",
            created_at="2026-01-01T00:00:00Z",
            payload={"x": 1},
            provenance=(),
        )
        assert a.artifact_hash != ""
        assert len(a.artifact_hash) == 64

    def test_register_connector(self):
        registry = {}
        ok, msg = register_connector(KubernetesConnector, KubernetesConnector.MANIFEST, registry)
        assert ok is True
        assert "kubernetes" in msg.lower() or "connector.kubernetes.v1" in msg

    def test_register_duplicate_fails(self):
        registry = {}
        register_connector(KubernetesConnector, KubernetesConnector.MANIFEST, registry)
        ok, msg = register_connector(KubernetesConnector, KubernetesConnector.MANIFEST, registry)
        assert ok is False


# ──────────────────────────────
#  Normalization Engine Tests
# ──────────────────────────────


class TestNormalizationEngine:
    def test_normalize_topology(self):
        artifact = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "n1", "type": "pod", "name": "app"}, {"id": "n2", "type": "svc", "name": "api"}],
            edges=[{"from": "n2", "to": "n1", "relation": "selects"}],
            source_system="k8s",
            connector_id="c1",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        assert artifact.artifact_family == "TopologyArtifact"
        assert artifact.payload["node_count"] == 2
        assert artifact.payload["edge_count"] == 1

    def test_normalize_identity_graph(self):
        artifact = ArtifactNormalizer.normalize_identity_graph(
            identities=[{"arn": "arn:aws:iam::123:role/Admin", "type": "role", "name": "Admin"}],
            relationships=[
                {"from": "arn:aws:iam::123:role/Admin", "to": "arn:aws:iam::123:policy/P1", "relation": "attached"}
            ],
            source_system="aws",
            connector_id="c1",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        assert artifact.artifact_family == "IdentityGraphArtifact"

    def test_normalize_dependency_graph(self):
        artifact = ArtifactNormalizer.normalize_dependency_graph(
            dependencies=[{"from": "a", "to": "b", "relation": "depends"}],
            source_system="tf",
            connector_id="c1",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        assert artifact.artifact_family == "DependencyGraphArtifact"

    def test_normalize_trace_topology(self):
        artifact = ArtifactNormalizer.normalize_trace_topology(
            spans=[{"span_id": "s1", "trace_id": "t1", "name": "GET /api"}],
            source_system="otel",
            connector_id="c1",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        assert artifact.artifact_family == "TraceTopologyArtifact"

    def test_normalize_infrastructure_state(self):
        artifact = ArtifactNormalizer.normalize_infrastructure_state(
            resources=[{"id": "r1", "type": "ec2", "region": "us-east-1"}],
            source_system="aws",
            connector_id="c1",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        assert artifact.artifact_family == "InfrastructureStateArtifact"

    def test_normalize_deployment_lineage(self):
        artifact = ArtifactNormalizer.normalize_deployment_lineage(
            deployments=[{"id": "d1", "name": "deploy", "status": "success"}],
            source_system="gha",
            connector_id="c1",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        assert artifact.artifact_family == "DeploymentLineageArtifact"

    def test_normalize_security_event(self):
        artifact = ArtifactNormalizer.normalize_security_event(
            events=[{"event_id": "e1", "action": "Allow", "principal": "user"}],
            source_system="aws",
            connector_id="c1",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        assert artifact.artifact_family == "SecurityEventArtifact"

    def test_canonicalize_list_deterministic(self):
        items = [{"id": "b"}, {"id": "a"}, {"id": "c"}]
        result = ArtifactNormalizer._canonicalize_list(items, key="id")
        assert [r["id"] for r in result] == ["a", "b", "c"]


# ──────────────────────────────
#  Connector Ingestion Tests
# ──────────────────────────────


class TestKubernetesConnector:
    def test_ingest_basic(self, k8s_connector):
        k8s_state = {
            "pods": [{"metadata": {"namespace": "default", "name": "pod1", "labels": {"app": "web"}}}],
            "services": [{"metadata": {"namespace": "default", "name": "svc1"}, "spec": {"selector": {"app": "web"}}}],
        }
        artifacts, receipt = k8s_connector.ingest("t1", "u1", "c1", raw_state=k8s_state)
        assert len(artifacts) == 2  # topology + state
        assert receipt.artifact_count == 2
        assert receipt.verify() is True

    def test_service_to_pod_edges(self, k8s_connector):
        k8s_state = {
            "pods": [{"metadata": {"namespace": "ns", "name": "pod1", "labels": {"app": "web"}}}],
            "services": [{"metadata": {"namespace": "ns", "name": "svc1"}, "spec": {"selector": {"app": "web"}}}],
        }
        artifacts, _ = k8s_connector.ingest("t1", "u1", "c1", raw_state=k8s_state)
        topo = artifacts[0]
        edges = topo.payload["edges"]
        assert any(e["relation"] == "selects" for e in edges)


class TestTerraformConnector:
    def test_ingest_resources(self, terraform_connector):
        tf_state = {
            "resources": [
                {
                    "module": "root",
                    "type": "aws_instance",
                    "name": "web",
                    "provider": "provider.aws",
                    "mode": "managed",
                    "instances": [{"attributes": {"ami": "ami-123"}}],
                    "depends_on": ["aws_vpc.main"],
                }
            ]
        }
        artifacts, receipt = terraform_connector.ingest("t1", "u1", "c1", raw_state=tf_state)
        assert len(artifacts) == 2  # state + dependencies
        assert receipt.artifact_count == 2


class TestOpenTelemetryConnector:
    def test_ingest_spans(self, otel_connector):
        raw = {"spans": [{"span_id": "s1", "trace_id": "t1", "name": "GET /api", "duration_ms": 12}]}
        artifacts, receipt = otel_connector.ingest("t1", "u1", "c1", raw_state=raw)
        assert len(artifacts) == 1
        assert artifacts[0].artifact_family == "TraceTopologyArtifact"


class TestAWSIAMConnector:
    def test_ingest_identities(self, iam_connector):
        raw = {
            "roles": [
                {
                    "Arn": "arn:aws:iam::123:role/Admin",
                    "RoleName": "Admin",
                    "AttachedPolicies": [{"PolicyArn": "arn:aws:iam::123:policy/P1"}],
                }
            ],
            "users": [{"Arn": "arn:aws:iam::123:user/Alice", "UserName": "Alice", "Groups": []}],
            "groups": [{"Arn": "arn:aws:iam::123:group/Engineers", "GroupName": "Engineers"}],
        }
        artifacts, receipt = iam_connector.ingest("t1", "u1", "c1", raw_state=raw)
        assert len(artifacts) == 1
        assert artifacts[0].artifact_family == "IdentityGraphArtifact"
        assert artifacts[0].payload["identity_count"] == 3


class TestGitHubActionsConnector:
    def test_ingest_deployments(self, gh_connector):
        raw = {
            "workflow_runs": [
                {
                    "id": 1,
                    "name": "CI",
                    "head_branch": "main",
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "success",
                    "created_at": "2026-01-01T00:00:00Z",
                }
            ]
        }
        artifacts, receipt = gh_connector.ingest("t1", "u1", "c1", raw_state=raw)
        assert len(artifacts) == 1
        assert artifacts[0].artifact_family == "DeploymentLineageArtifact"


class TestDockerConnector:
    def test_ingest_topology(self, docker_connector):
        raw = {
            "containers": [
                {"Id": "c1", "Names": ["web"], "Image": "nginx", "NetworkSettings": {"Networks": {"bridge": {}}}}
            ],
            "images": [{"Id": "i1", "RepoTags": ["nginx:latest"]}],
            "networks": [{"Id": "n1", "Name": "bridge"}],
        }
        artifacts, receipt = docker_connector.ingest("t1", "u1", "c1", raw_state=raw)
        assert len(artifacts) == 2
        topo = artifacts[0]
        assert any(n["type"] == "container" for n in topo.payload["nodes"])


class TestPostgreSQLConnector:
    def test_ingest_schema(self, pg_connector):
        raw = {
            "tables": [
                {
                    "schema": "public",
                    "name": "users",
                    "columns": [{"name": "id", "type": "int"}],
                    "foreign_keys": [{"ref_schema": "public", "ref_table": "accounts", "columns": ["account_id"]}],
                }
            ]
        }
        artifacts, receipt = pg_connector.ingest("t1", "u1", "c1", raw_state=raw)
        assert len(artifacts) == 2
        dep = artifacts[0]
        assert dep.artifact_family == "DependencyGraphArtifact"
        assert dep.payload["dependency_count"] == 1


# ──────────────────────────────
#  Marketplace + Governance Tests
# ──────────────────────────────


class TestConnectorMarketplace:
    def test_register_manifest(self, marketplace):
        ok, msg = marketplace.register(KubernetesConnector.MANIFEST)
        assert ok is True
        assert "kubernetes" in msg.lower()

    def test_register_duplicate_fails(self, marketplace):
        marketplace.register(KubernetesConnector.MANIFEST)
        ok, msg = marketplace.register(KubernetesConnector.MANIFEST)
        assert ok is False

    def test_get_manifest(self, marketplace):
        marketplace.register(KubernetesConnector.MANIFEST)
        m = marketplace.get_manifest("connector.kubernetes.v1", "1.0.0")
        assert m is not None
        assert m.connector_id == "connector.kubernetes.v1"

    def test_list_by_trust_tier(self, marketplace):
        marketplace.register(KubernetesConnector.MANIFEST)
        results = marketplace.list_connectors(trust_tier="unverified")
        assert len(results) >= 1

    def test_sign_and_verify(self, marketplace):
        marketplace.register(KubernetesConnector.MANIFEST)
        sig = marketplace.sign_connector("connector.kubernetes.v1", "1.0.0", "signer_1")
        assert len(sig) == 64
        assert marketplace.verify_signature("connector.kubernetes.v1", "1.0.0") is True

    def test_sign_unknown_fails(self, marketplace):
        with pytest.raises(ValueError):
            marketplace.sign_connector("unknown", "1.0.0", "signer_1")


class TestConnectorGovernance:
    def test_allow_verified_connector(self, marketplace, governance_engine):
        marketplace.register(KubernetesConnector.MANIFEST)
        # Create governance rule: allow verified connectors
        rule = GovernanceRule(
            rule_id="allow_verified",
            name="Allow Verified",
            description="",
            target_scope="global",
            conditions=(
                Condition("action", ConditionOperator.EQUALS, "connector:ingest"),
                Condition("connector_trust_tier", ConditionOperator.IN_SET, ["verified", "certified"]),
            ),
            effect=Effect.ALLOW,
            priority=1,
            version="1",
        )
        governance_engine.load_policy(PolicyCompiler.compile(rule))

        cg = ConnectorGovernance(marketplace, governance_engine)
        decision = cg.evaluate_connector_ingestion(
            "connector.kubernetes.v1",
            "1.0.0",
            "t1",
            "u1",
            "c1",
        )
        # K8s connector is unverified by default, so DENY
        assert decision.effect == Effect.DENY

    def test_allow_any_connector_with_policy(self, marketplace, governance_engine):
        marketplace.register(KubernetesConnector.MANIFEST)
        rule = GovernanceRule(
            rule_id="allow_all",
            name="Allow All Connectors",
            description="",
            target_scope="global",
            conditions=(Condition("action", ConditionOperator.EQUALS, "connector:ingest"),),
            effect=Effect.ALLOW,
            priority=1,
            version="1",
        )
        governance_engine.load_policy(PolicyCompiler.compile(rule))
        cg = ConnectorGovernance(marketplace, governance_engine)
        decision = cg.evaluate_connector_ingestion(
            "connector.kubernetes.v1",
            "1.0.0",
            "t1",
            "u1",
            "c1",
        )
        assert decision.effect == Effect.ALLOW

    def test_unknown_connector_denied(self, marketplace, governance_engine):
        cg = ConnectorGovernance(marketplace, governance_engine)
        decision = cg.evaluate_connector_ingestion(
            "unknown",
            "1.0.0",
            "t1",
            "u1",
            "c1",
        )
        assert decision.effect == Effect.DENY
        assert decision.denied_by == "governance:unknown_connector"

    def test_enforce_minimum_trust(self, marketplace):
        marketplace.register(KubernetesConnector.MANIFEST)
        cg = ConnectorGovernance(marketplace, GovernanceEngine())
        assert cg.enforce_minimum_trust("connector.kubernetes.v1", "1.0.0", "unverified") is True
        assert cg.enforce_minimum_trust("connector.kubernetes.v1", "1.0.0", "verified") is False
        assert cg.enforce_minimum_trust("unknown", "1.0.0", "unverified") is False


# ──────────────────────────────
#  Cross-System Topology Tests
# ──────────────────────────────


class TestCrossSystemTopology:
    def test_unified_graph_add_artifact(self):
        graph = UnifiedTopologyGraph("t1", "c1")
        artifact = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "n1", "type": "pod"}, {"id": "n2", "type": "svc"}],
            edges=[{"from": "n1", "to": "n2", "relation": "serves"}],
            source_system="k8s",
            connector_id="c1",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        nodes = graph.add_artifact(artifact)
        assert len(nodes) == 2
        assert graph.get_node("n1") is not None
        assert graph.get_node("n2") is not None

    def test_unified_graph_hash_deterministic(self):
        graph = UnifiedTopologyGraph("t1", "c1")
        artifact = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "a", "type": "x"}, {"id": "b", "type": "y"}],
            edges=[{"from": "a", "to": "b", "relation": "r"}],
            source_system="s",
            connector_id="c1",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        graph.add_artifact(artifact)
        h1 = graph.graph_hash()
        # Build identical graph
        graph2 = UnifiedTopologyGraph("t1", "c1")
        graph2.add_artifact(artifact)
        h2 = graph2.graph_hash()
        assert h1 == h2
        assert len(h1) == 64

    def test_cross_system_link(self):
        graph = UnifiedTopologyGraph("t1", "c1")
        artifact1 = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "k8s:svc1", "type": "service"}],
            edges=[],
            source_system="k8s",
            connector_id="c1",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        artifact2 = ArtifactNormalizer.normalize_infrastructure_state(
            resources=[{"id": "tf:svc1", "type": "aws_lb"}],
            source_system="tf",
            connector_id="c2",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        graph.add_artifact(artifact1)
        graph.add_artifact(artifact2)
        edge = graph.add_cross_system_link("k8s:svc1", "tf:svc1", "managed_by", "manual_link")
        assert edge.from_node == "k8s:svc1"
        assert edge.relation == "managed_by"

    def test_cross_system_dependency_graph(self):
        csd = CrossSystemDependencyGraph("t1")
        a1 = NormalizedArtifact(
            artifact_id="a1",
            artifact_family="X",
            artifact_schema_version="1",
            source_system="k8s",
            connector_id="c1",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
            created_at="2026-01-01T00:00:00Z",
            payload={"resources": [{"name": "web"}]},
            provenance=(),
        )
        a2 = NormalizedArtifact(
            artifact_id="a2",
            artifact_family="Y",
            artifact_schema_version="1",
            source_system="tf",
            connector_id="c2",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
            created_at="2026-01-01T00:00:00Z",
            payload={"resources": [{"name": "web"}]},
            provenance=(),
        )
        csd.register_artifact(a1)
        csd.register_artifact(a2)
        csd.add_link_rule("k8s", "tf", "resources.0.name", "resources.0.name", "same_name")
        links = csd.get_links("k8s", "tf")
        assert len(links) == 1
        assert links[0][2] == "same_name"

    def test_risk_blast_radius(self):
        graph = UnifiedTopologyGraph("t1", "c1")
        for i in range(5):
            a = ArtifactNormalizer.normalize_topology(
                nodes=[{"id": f"n{i}", "type": "node"}],
                edges=[{"from": f"n{i}", "to": f"n{(i + 1) % 5}", "relation": "connects"}],
                source_system="s",
                connector_id="c",
                connector_version="1",
                tenant_id="t1",
                correlation_id="c1",
            )
            graph.add_artifact(a)

        risk = RiskPropagationTopology(graph)
        blast = risk.blast_radius("n0", max_hops=3)
        assert blast["origin"] == "n0"
        assert blast["reachable_count"] > 0

    def test_risk_critical_path(self):
        graph = UnifiedTopologyGraph("t1", "c1")
        for i in range(4):
            a = ArtifactNormalizer.normalize_topology(
                nodes=[{"id": f"n{i}", "type": "node"}],
                edges=[{"from": f"n{i}", "to": f"n{i + 1}", "relation": "link"}] if i < 3 else [],
                source_system="s",
                connector_id="c",
                connector_version="1",
                tenant_id="t1",
                correlation_id="c1",
            )
            graph.add_artifact(a)
        risk = RiskPropagationTopology(graph)
        path = risk.critical_path("n0", "n3")
        assert path is not None
        assert path[0] == "n0"
        assert path[-1] == "n3"

    def test_risk_critical_path_no_path(self):
        graph = UnifiedTopologyGraph("t1", "c1")
        a = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "a", "type": "x"}, {"id": "b", "type": "y"}],
            edges=[],
            source_system="s",
            connector_id="c",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        graph.add_artifact(a)
        risk = RiskPropagationTopology(graph)
        assert risk.critical_path("a", "b") is None


# ──────────────────────────────
#  Digital Twin Import + Replay Tests
# ──────────────────────────────


class TestDigitalTwinImport:
    def test_import_artifact(self):
        dt = DigitalTwinImport("t1")
        artifact = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "n1", "type": "pod"}],
            edges=[],
            source_system="k8s",
            connector_id="c",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        node = dt.import_artifact(artifact)
        assert node.node_id == "n1"
        assert node.system == "k8s"

    def test_snapshot_topology(self):
        dt = DigitalTwinImport("t1")
        for i in range(3):
            a = ArtifactNormalizer.normalize_topology(
                nodes=[{"id": f"n{i}", "type": "node"}],
                edges=[{"from": f"n{i}", "to": f"n{(i + 1) % 3}", "relation": "link"}],
                source_system="s",
                connector_id="c",
                connector_version="1",
                tenant_id="t1",
                correlation_id="c1",
            )
            dt.import_artifact(a)
        snap = dt.snapshot_topology()
        assert snap["node_count"] == 3
        assert snap["edge_count"] == 3
        assert snap["graph_hash"] != ""

    def test_drift_analysis(self):
        dt = DigitalTwinImport("t1")
        a1 = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "n1", "type": "pod"}, {"id": "n2", "type": "svc"}],
            edges=[{"from": "n1", "to": "n2", "relation": "link"}],
            source_system="k8s",
            connector_id="c",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        dt.import_artifact(a1)

        # Previous topology
        prev = UnifiedTopologyGraph("t1", "prev")
        prev.add_artifact(a1)

        # Add new artifact to current
        a2 = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "n3", "type": "deploy"}],
            edges=[],
            source_system="k8s",
            connector_id="c",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        dt.import_artifact(a2)

        drift = dt.drift_analysis(prev)
        assert "n3" in drift["added_nodes"]
        assert drift["stable"] is False
        assert drift["drift_hash"] != ""

    def test_drift_stable(self):
        dt = DigitalTwinImport("t1")
        a = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "n1", "type": "pod"}],
            edges=[],
            source_system="k8s",
            connector_id="c",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        dt.import_artifact(a)
        prev = UnifiedTopologyGraph("t1", "prev")
        prev.add_artifact(a)
        drift = dt.drift_analysis(prev)
        assert drift["stable"] is True

    def test_incident_reconstruction(self):
        dt = DigitalTwinImport("t1")
        for i in range(3):
            a = ArtifactNormalizer.normalize_topology(
                nodes=[{"id": f"n{i}", "type": "node"}],
                edges=[{"from": f"n{i}", "to": f"n{(i + 1) % 3}", "relation": "link"}],
                source_system="s",
                connector_id="c",
                connector_version="1",
                tenant_id="t1",
                correlation_id="c1",
            )
            dt.import_artifact(a)
        incident = dt.incident_reconstruction("n0", max_hops=2)
        assert incident["origin"] == "n0"
        assert len(incident["affected_systems"]) > 0

    def test_temporal_replay(self):
        dt = DigitalTwinImport("t1")
        a = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "n1", "type": "pod"}],
            edges=[],
            source_system="k8s",
            connector_id="c",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        dt.import_artifact(a)
        receipt = IngestionReceipt(
            receipt_id="r1",
            connector_id="c",
            connector_version="1",
            tenant_id="t1",
            actor_id="u1",
            correlation_id="c1",
            ingestion_start="2026-01-01T00:00:00Z",
            ingestion_end="2026-01-01T00:00:01Z",
            artifact_count=1,
            artifact_hashes=(a.artifact_hash,),
            fence_used=ConnectorExecutionFence.SANDBOXED_READ,
            sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
            error_count=0,
            errors=(),
        )
        dt.import_receipt(receipt)
        replay = dt.temporal_replay([receipt], [])
        assert replay["steps"] == 1
        assert replay["final_node_count"] == 1
        assert replay["replay_hash"] != ""

    def test_cross_system_links_in_digital_twin(self):
        dt = DigitalTwinImport("t1")
        a1 = NormalizedArtifact(
            artifact_id="a1",
            artifact_family="X",
            artifact_schema_version="1",
            source_system="k8s",
            connector_id="c1",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
            created_at="2026-01-01T00:00:00Z",
            payload={"resources": [{"name": "web"}]},
            provenance=(),
        )
        a2 = NormalizedArtifact(
            artifact_id="a2",
            artifact_family="Y",
            artifact_schema_version="1",
            source_system="tf",
            connector_id="c2",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
            created_at="2026-01-01T00:00:00Z",
            payload={"resources": [{"name": "web"}]},
            provenance=(),
        )
        dt.import_artifact(a1)
        dt.import_artifact(a2)
        dt.build_cross_system_links(
            [
                {
                    "from_system": "k8s",
                    "to_system": "tf",
                    "from_field": "resources.0.name",
                    "to_field": "resources.0.name",
                    "relation": "same_name",
                }
            ]
        )
        snap = dt.snapshot_topology()
        # Both artifacts + cross-system edge
        assert snap["edge_count"] >= 1


# ──────────────────────────────
#  End-to-End Integration
# ──────────────────────────────


class TestConnectorFabricIntegration:
    def test_full_pipeline_k8s_terraform(self, marketplace, governance_engine):
        # Register connectors
        marketplace.register(KubernetesConnector.MANIFEST)
        marketplace.register(TerraformStateConnector.MANIFEST)

        # K8s ingestion
        k8s = KubernetesConnector(KubernetesConnector.MANIFEST, {})
        k8s_state = {
            "pods": [{"metadata": {"namespace": "prod", "name": "api", "labels": {"tier": "frontend"}}}],
            "services": [
                {"metadata": {"namespace": "prod", "name": "api-svc"}, "spec": {"selector": {"tier": "frontend"}}}
            ],
        }
        k8s_artifacts, k8s_receipt = k8s.ingest("t1", "u1", "run_1", raw_state=k8s_state)

        # Terraform ingestion
        tf = TerraformStateConnector(TerraformStateConnector.MANIFEST, {})
        tf_state = {
            "resources": [
                {
                    "module": "root",
                    "type": "aws_instance",
                    "name": "api",
                    "mode": "managed",
                    "provider": "aws",
                    "instances": [{"attributes": {"ami": "ami-123"}}],
                    "depends_on": [],
                }
            ]
        }
        tf_artifacts, tf_receipt = tf.ingest("t1", "u1", "run_1", raw_state=tf_state)

        # Build digital twin
        dt = DigitalTwinImport("t1")
        for a in k8s_artifacts + tf_artifacts:
            dt.import_artifact(a)
        dt.import_receipt(k8s_receipt)
        dt.import_receipt(tf_receipt)

        snap = dt.snapshot_topology()
        assert snap["artifact_count"] == 4
        assert snap["receipt_count"] == 2
        assert snap["graph_hash"] != ""

    def test_governed_connector_with_marketplace(self, marketplace, governance_engine):
        marketplace.register(KubernetesConnector.MANIFEST)
        marketplace.register(AWSIAMConnector.MANIFEST)

        # Allow only topology_read connectors
        rule = GovernanceRule(
            rule_id="allow_topology",
            name="Allow Topology",
            description="",
            target_scope="global",
            conditions=(
                Condition("action", ConditionOperator.EQUALS, "connector:ingest"),
                Condition("connector_trust_tier", ConditionOperator.IN_SET, ["unverified", "community", "verified"]),
            ),
            effect=Effect.ALLOW,
            priority=1,
            version="1",
        )
        governance_engine.load_policy(PolicyCompiler.compile(rule))
        cg = ConnectorGovernance(marketplace, governance_engine)

        d1 = cg.evaluate_connector_ingestion("connector.kubernetes.v1", "1.0.0", "t1", "u1", "c1")
        assert d1.effect == Effect.ALLOW

        d2 = cg.evaluate_connector_ingestion("connector.aws_iam.v1", "1.0.0", "t1", "u1", "c1")
        assert d2.effect == Effect.ALLOW

    def test_all_seven_connectors_produce_receipts(self):
        connectors = [
            KubernetesConnector(KubernetesConnector.MANIFEST, {}),
            TerraformStateConnector(TerraformStateConnector.MANIFEST, {}),
            OpenTelemetryConnector(OpenTelemetryConnector.MANIFEST, {}),
            AWSIAMConnector(AWSIAMConnector.MANIFEST, {}),
            GitHubActionsConnector(GitHubActionsConnector.MANIFEST, {}),
            DockerConnector(DockerConnector.MANIFEST, {}),
            PostgreSQLConnector(PostgreSQLConnector.MANIFEST, {}),
        ]
        for c in connectors:
            artifacts, receipt = c.ingest("t1", "u1", "test_run")
            assert receipt.verify() is True
            assert receipt.connector_id == c.manifest.connector_id
            assert receipt.sandbox_policy == ConnectorSandboxPolicy.READ_ONLY
            assert receipt.fence_used == ConnectorExecutionFence.SANDBOXED_READ

    def test_multi_tenant_isolation_in_topology(self):
        dt_t1 = DigitalTwinImport("tenant_a")
        dt_t2 = DigitalTwinImport("tenant_b")

        a1 = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "n1", "type": "pod"}],
            edges=[],
            source_system="k8s",
            connector_id="c",
            connector_version="1",
            tenant_id="tenant_a",
            correlation_id="c1",
        )
        a2 = ArtifactNormalizer.normalize_topology(
            nodes=[{"id": "n1", "type": "pod"}],
            edges=[],
            source_system="k8s",
            connector_id="c",
            connector_version="1",
            tenant_id="tenant_b",
            correlation_id="c1",
        )
        dt_t1.import_artifact(a1)
        dt_t2.import_artifact(a2)

        assert dt_t1.snapshot_topology()["node_count"] == 1
        assert dt_t2.snapshot_topology()["node_count"] == 1
        # Graphs are identical (same payload), so hash is same
        assert dt_t1.snapshot_topology()["graph_hash"] == dt_t2.snapshot_topology()["graph_hash"]
        # But tenants are isolated (different DigitalTwinImport instances)

    def test_connector_manifest_compatibility(self):
        m = KubernetesConnector.MANIFEST
        assert ConnectorCapabilityClass.TOPOLOGY_READ in m.capability_classes
        assert m.sandbox_policy == ConnectorSandboxPolicy.READ_ONLY
        assert "kubernetes" in m.target_systems
        assert m.manifest_hash != ""

    def test_topology_graph_with_dependencies(self):
        graph = UnifiedTopologyGraph("t1", "c1")
        a = ArtifactNormalizer.normalize_dependency_graph(
            dependencies=[
                {"from": "svc:a", "to": "svc:b", "relation": "calls"},
                {"from": "svc:b", "to": "db:c", "relation": "connects"},
            ],
            source_system="k8s",
            connector_id="c",
            connector_version="1",
            tenant_id="t1",
            correlation_id="c1",
        )
        graph.add_artifact(a)
        assert graph.get_neighbors("svc:a") == ["svc:b"]
        assert graph.get_neighbors("svc:b") == ["db:c"]

    def test_risk_blast_radius_multi_hop(self):
        graph = UnifiedTopologyGraph("t1", "c1")
        for i in range(10):
            a = ArtifactNormalizer.normalize_topology(
                nodes=[{"id": f"node_{i}", "type": "service"}],
                edges=[{"from": f"node_{i}", "to": f"node_{(i + 1) % 10}", "relation": "calls"}],
                source_system="mesh",
                connector_id="c",
                connector_version="1",
                tenant_id="t1",
                correlation_id="c1",
            )
            graph.add_artifact(a)
        risk = RiskPropagationTopology(graph)
        blast = risk.blast_radius("node_0", max_hops=5)
        assert blast["reachable_count"] == 5  # nodes 1,2,3,4,5
        assert "node_5" in blast["reachable_nodes"]
        assert "node_6" not in blast["reachable_nodes"]

    def test_replay_hash_determinism(self):
        dt = DigitalTwinImport("t1")
        artifacts = []
        for i in range(3):
            a = ArtifactNormalizer.normalize_topology(
                nodes=[{"id": f"n{i}", "type": "node"}],
                edges=[],
                source_system="s",
                connector_id="c",
                connector_version="1",
                tenant_id="t1",
                correlation_id="c1",
            )
            dt.import_artifact(a)
            artifacts.append(a)

        receipts = [
            IngestionReceipt(
                receipt_id=f"r{i}",
                connector_id="c",
                connector_version="1",
                tenant_id="t1",
                actor_id="u1",
                correlation_id="c1",
                ingestion_start="2026-01-01T00:00:00Z",
                ingestion_end="2026-01-01T00:00:01Z",
                artifact_count=1,
                artifact_hashes=(a.artifact_hash,),
                fence_used=ConnectorExecutionFence.SANDBOXED_READ,
                sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
                error_count=0,
                errors=(),
            )
            for i, a in enumerate(artifacts)
        ]
        for r in receipts:
            dt.import_receipt(r)

        replay = dt.temporal_replay(receipts, [])
        replay2 = dt.temporal_replay(receipts, [])
        assert replay["replay_hash"] == replay2["replay_hash"]
        assert len(replay["replay_hash"]) == 64


# ──────────────────────────────
#  Reproducibility Regression (determinism contract)
# ──────────────────────────────


class TestHashReproducibility:
    """Regression tests for the "deterministic kernel" claim.

    A content/identity hash must be a pure function of the LOGICAL content of an
    object. It must NOT vary because of wall-clock timestamps or random ids.
    These tests build the SAME logical object twice (two fresh instances,
    deliberately separated by a sleep so any wall-clock contamination would
    differ) and assert IDENTICAL hashes, while also asserting the wall-clock
    metadata is still recorded.
    """

    @staticmethod
    def _k8s_state():
        return {
            "pods": [{"metadata": {"namespace": "default", "name": "pod1", "labels": {"app": "web"}}}],
            "services": [
                {"metadata": {"namespace": "default", "name": "svc1"}, "spec": {"selector": {"app": "web"}}}
            ],
        }

    def test_ingestion_receipt_hash_is_reproducible(self):
        # Two fresh ingestion runs of identical logical input. Wall-clock
        # ingestion_start/ingestion_end differ between runs, but receipt_hash
        # must not.
        c1 = KubernetesConnector(KubernetesConnector.MANIFEST, {})
        _, r1 = c1.ingest("t1", "u1", "run_1", raw_state=self._k8s_state())
        time.sleep(0.01)
        c2 = KubernetesConnector(KubernetesConnector.MANIFEST, {})
        _, r2 = c2.ingest("t1", "u1", "run_1", raw_state=self._k8s_state())

        # Identity hash is reproducible despite differing wall-clock metadata.
        assert r1.receipt_hash == r2.receipt_hash
        assert len(r1.receipt_hash) == 64

        # The timestamps are still RECORDED as metadata (not deleted), and they
        # genuinely capture wall-clock time (so they differ between the runs).
        assert r1.ingestion_start and r1.ingestion_end
        assert r2.ingestion_start and r2.ingestion_end
        assert (r1.ingestion_start, r1.ingestion_end) != (r2.ingestion_start, r2.ingestion_end)

        # Receipts must still self-verify.
        assert r1.verify() is True
        assert r2.verify() is True

    def test_ingestion_receipt_hash_excludes_wall_clock(self):
        # Same logical receipt, different wall-clock timestamps -> same hash.
        common = dict(
            receipt_id="r1",
            connector_id="c1",
            connector_version="1.0.0",
            tenant_id="t1",
            actor_id="a1",
            correlation_id="c1",
            artifact_count=2,
            artifact_hashes=("h1", "h2"),
            fence_used=ConnectorExecutionFence.SANDBOXED_READ,
            sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
            error_count=0,
            errors=(),
        )
        r1 = IngestionReceipt(
            ingestion_start="2026-01-01T00:00:00Z",
            ingestion_end="2026-01-01T00:00:01Z",
            **common,
        )
        r2 = IngestionReceipt(
            ingestion_start="2030-12-31T23:59:59Z",
            ingestion_end="2031-01-01T00:00:42Z",
            **common,
        )
        assert r1.receipt_hash == r2.receipt_hash
        # But the timestamps themselves are still stored distinctly.
        assert r1.ingestion_start != r2.ingestion_start
        assert r1.to_dict()["ingestion_start"] == "2026-01-01T00:00:00Z"

    def test_normalized_artifact_hash_is_reproducible(self):
        # artifact_hash already excludes created_at; lock that contract in.
        def build():
            return ArtifactNormalizer.normalize_topology(
                nodes=[{"id": "n2", "type": "svc"}, {"id": "n1", "type": "pod"}],
                edges=[{"from": "n2", "to": "n1", "relation": "selects"}],
                source_system="k8s",
                connector_id="c1",
                connector_version="1",
                tenant_id="t1",
                correlation_id="c1",
            )

        a1 = build()
        time.sleep(0.01)
        a2 = build()
        assert a1.artifact_hash == a2.artifact_hash
        assert len(a1.artifact_hash) == 64
        # created_at is still recorded and reflects real wall-clock time.
        assert a1.created_at and a2.created_at
        assert a1.created_at != a2.created_at

    def test_snapshot_graph_hash_is_reproducible(self):
        # The snapshot's identity is its graph_hash, which must be content
        # addressed. snapshot_at remains recorded wall-clock metadata.
        def build_snapshot():
            dt = DigitalTwinImport("t1")
            for i in range(3):
                a = ArtifactNormalizer.normalize_topology(
                    nodes=[{"id": f"n{i}", "type": "node"}],
                    edges=[{"from": f"n{i}", "to": f"n{(i + 1) % 3}", "relation": "link"}],
                    source_system="s",
                    connector_id="c",
                    connector_version="1",
                    tenant_id="t1",
                    correlation_id="c1",
                )
                dt.import_artifact(a)
            return dt.snapshot_topology()

        s1 = build_snapshot()
        time.sleep(0.01)
        s2 = build_snapshot()
        assert s1["graph_hash"] == s2["graph_hash"]
        assert len(s1["graph_hash"]) == 64
        # snapshot_at metadata is still present and reflects wall-clock time.
        assert s1["snapshot_at"] and s2["snapshot_at"]
        assert s1["snapshot_at"] != s2["snapshot_at"]
