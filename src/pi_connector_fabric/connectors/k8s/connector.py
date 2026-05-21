"""Kubernetes Connector — read-only ingestion of K8s cluster state.

Deterministic connector that normalizes Kubernetes resources into canonical
TopologyArtifact + InfrastructureStateArtifact.

No external API calls in deterministic mode. Operates on API responses or
exported state files that are provided as input.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

from pi_connector_fabric.sdk.core import (
    ArtifactNormalizer,
    BaseConnectorWorker,
    ConnectorCapabilityClass,
    ConnectorManifest,
    ConnectorSandboxPolicy,
    IngestionReceipt,
    NormalizedArtifact,
)


class KubernetesConnector(BaseConnectorWorker):
    """Ingest Kubernetes cluster state deterministically.

    Input: dict of K8s resources by type (pods, services, deployments, etc.)
    Output: TopologyArtifact + InfrastructureStateArtifact
    """

    MANIFEST = ConnectorManifest(
        connector_id="connector.kubernetes.v1",
        name="Kubernetes Cluster Connector",
        version="1.0.0",
        description="Ingests Kubernetes cluster state into semantic artifacts",
        capability_classes=(
            ConnectorCapabilityClass.TOPOLOGY_READ,
            ConnectorCapabilityClass.STATE_READ,
            ConnectorCapabilityClass.DEPENDENCY_READ,
        ),
        sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
        target_systems=("kubernetes", "k8s", "openshift"),
        output_schemas=("TopologyArtifact", "InfrastructureStateArtifact"),
        required_credentials=(),
        config_schema={
            "type": "object",
            "properties": {
                "namespace_filter": {"type": "array", "items": {"type": "string"}},
                "include_events": {"type": "boolean"},
            },
        },
    )

    def ingest(
        self,
        tenant_id: str,
        actor_id: str,
        correlation_id: str,
        **kwargs: Any,
    ) -> Tuple[List[NormalizedArtifact], IngestionReceipt]:
        """Ingest K8s cluster state into canonical artifacts.

        Expects k8s_state in kwargs from the config or external data source.
        """
        start = datetime.now(timezone.utc).isoformat()
        errors: List[str] = []
        artifacts: List[NormalizedArtifact] = []

        k8s_state = kwargs.get("raw_state", self.config.get("raw_state", {}))

        # Extract nodes
        nodes = self._extract_nodes(k8s_state)
        # Extract edges (relationships)
        edges = self._extract_edges(k8s_state)
        # Extract resources for state artifact
        resources = self._extract_resources(k8s_state)

        # Topology artifact
        topology = ArtifactNormalizer.normalize_topology(
            nodes=nodes,
            edges=edges,
            source_system="kubernetes",
            connector_id=self.manifest.connector_id,
            connector_version=self.manifest.version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
        )
        artifacts.append(topology)

        # Infrastructure state artifact
        state = ArtifactNormalizer.normalize_infrastructure_state(
            resources=resources,
            source_system="kubernetes",
            connector_id=self.manifest.connector_id,
            connector_version=self.manifest.version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
        )
        artifacts.append(state)

        receipt = self._produce_receipt(
            artifacts=artifacts,
            tenant_id=tenant_id,
            actor_id=actor_id,
            correlation_id=correlation_id,
            start_time=start,
            errors=errors,
        )
        return artifacts, receipt

    def _extract_nodes(self, state: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        nodes: List[Dict[str, Any]] = []
        for resource_type, resources in state.items():
            for resource in resources:
                metadata = resource.get("metadata", {})
                nodes.append({
                    "id": f"k8s:{resource_type}:{metadata.get('namespace','default')}:{metadata.get('name','unknown')}",
                    "type": resource_type,
                    "namespace": metadata.get("namespace", "default"),
                    "name": metadata.get("name", "unknown"),
                    "labels": metadata.get("labels", {}),
                    "annotations": metadata.get("annotations", {}),
                })
        return nodes

    def _extract_edges(self, state: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []
        # Map services to pods via selector
        services = state.get("services", [])
        pods = state.get("pods", [])
        for svc in services:
            svc_meta = svc.get("metadata", {})
            svc_id = f"k8s:services:{svc_meta.get('namespace','default')}:{svc_meta.get('name','unknown')}"
            selector = svc.get("spec", {}).get("selector", {})
            for pod in pods:
                pod_meta = pod.get("metadata", {})
                pod_labels = pod_meta.get("labels", {})
                if all(pod_labels.get(k) == v for k, v in selector.items()):
                    pod_id = f"k8s:pods:{pod_meta.get('namespace','default')}:{pod_meta.get('name','unknown')}"
                    edges.append({"from": svc_id, "to": pod_id, "relation": "selects"})
        return edges

    def _extract_resources(self, state: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        resources: List[Dict[str, Any]] = []
        for resource_type, items in state.items():
            for item in items:
                metadata = item.get("metadata", {})
                resources.append({
                    "id": f"k8s:{resource_type}:{metadata.get('namespace','default')}:{metadata.get('name','unknown')}",
                    "type": resource_type,
                    "namespace": metadata.get("namespace", "default"),
                    "name": metadata.get("name", "unknown"),
                    "api_version": item.get("apiVersion", "v1"),
                    "kind": item.get("kind", resource_type),
                    "uid": metadata.get("uid", ""),
                })
        return resources
