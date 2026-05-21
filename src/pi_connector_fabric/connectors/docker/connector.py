"""Docker Runtime Connector — read-only ingestion of container runtime state.

Deterministic connector that normalizes Docker containers, images, networks,
volumes into InfrastructureStateArtifact + TopologyArtifact.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, List, Tuple

from pi_connector_fabric.sdk.core import (
    ArtifactNormalizer,
    BaseConnectorWorker,
    ConnectorCapabilityClass,
    ConnectorManifest,
    ConnectorSandboxPolicy,
    IngestionReceipt,
    NormalizedArtifact,
)


class DockerConnector(BaseConnectorWorker):
    """Ingest Docker runtime state deterministically."""

    MANIFEST = ConnectorManifest(
        connector_id="connector.docker.v1",
        name="Docker Runtime Connector",
        version="1.0.0",
        description="Ingests Docker container runtime state",
        capability_classes=(
            ConnectorCapabilityClass.TOPOLOGY_READ,
            ConnectorCapabilityClass.STATE_READ,
        ),
        sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
        target_systems=("docker", "containerd"),
        output_schemas=("TopologyArtifact", "InfrastructureStateArtifact"),
        required_credentials=(),
        config_schema={
            "type": "object",
            "properties": {
                "include_stopped": {"type": "boolean"},
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
        start = datetime.now(timezone.utc).isoformat()
        errors: List[str] = []
        artifacts: List[NormalizedArtifact] = []

        raw = kwargs.get("raw_state", self.config.get("raw_state", {}))
        containers = raw.get("containers", [])
        images = raw.get("images", [])
        networks = raw.get("networks", [])

        # Topology: containers on networks
        nodes = [
            {"id": f"docker:container:{c.get('Id','')}", "type": "container", "name": c.get("Names", [""])[0], "image": c.get("Image", "")}
            for c in containers
        ]
        nodes += [
            {"id": f"docker:network:{n.get('Id','')}", "type": "network", "name": n.get("Name", "")}
            for n in networks
        ]
        edges = []
        for c in containers:
            for net_name in c.get("NetworkSettings", {}).get("Networks", {}).keys():
                cid = f"docker:container:{c.get('Id','')}"
                nid = f"docker:network:{net_name}"
                edges.append({"from": cid, "to": nid, "relation": "connected_to"})

        topology = ArtifactNormalizer.normalize_topology(
            nodes=nodes, edges=edges, source_system="docker",
            connector_id=self.manifest.connector_id, connector_version=self.manifest.version,
            tenant_id=tenant_id, correlation_id=correlation_id,
        )
        artifacts.append(topology)

        # State
        resources = [
            {"id": f"docker:container:{c.get('Id','')}", "type": "container", "state": c.get("State", {}), "image": c.get("Image", "")}
            for c in containers
        ]
        resources += [
            {"id": f"docker:image:{i.get('Id','')}", "type": "image", "tags": i.get("RepoTags", [])}
            for i in images
        ]

        state = ArtifactNormalizer.normalize_infrastructure_state(
            resources=resources, source_system="docker",
            connector_id=self.manifest.connector_id, connector_version=self.manifest.version,
            tenant_id=tenant_id, correlation_id=correlation_id,
        )
        artifacts.append(state)

        receipt = self._produce_receipt(
            artifacts=artifacts, tenant_id=tenant_id, actor_id=actor_id,
            correlation_id=correlation_id, start_time=start, errors=errors,
        )
        return artifacts, receipt
