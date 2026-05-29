"""Terraform State Connector — read-only ingestion of Terraform state.

Deterministic connector that normalizes Terraform state into canonical
InfrastructureStateArtifact + DependencyGraphArtifact.
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


class TerraformStateConnector(BaseConnectorWorker):
    """Ingest Terraform state deterministically."""

    MANIFEST = ConnectorManifest(
        connector_id="connector.terraform.v1",
        name="Terraform State Connector",
        version="1.0.0",
        description="Ingests Terraform state into semantic artifacts",
        capability_classes=(
            ConnectorCapabilityClass.STATE_READ,
            ConnectorCapabilityClass.DEPENDENCY_READ,
            ConnectorCapabilityClass.LINEAGE_READ,
        ),
        sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
        target_systems=("terraform", "opentofu", "terragrunt"),
        output_schemas=("InfrastructureStateArtifact", "DependencyGraphArtifact"),
        required_credentials=(),
        config_schema={
            "type": "object",
            "properties": {
                "state_format": {"type": "string", "enum": ["v3", "v4"]},
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

        tf_state = kwargs.get("raw_state", self.config.get("raw_state", {}))

        resources = self._extract_resources(tf_state)
        dependencies = self._extract_dependencies(tf_state)

        state_artifact = ArtifactNormalizer.normalize_infrastructure_state(
            resources=resources,
            source_system="terraform",
            connector_id=self.manifest.connector_id,
            connector_version=self.manifest.version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
        )
        artifacts.append(state_artifact)

        dep_artifact = ArtifactNormalizer.normalize_dependency_graph(
            dependencies=dependencies,
            source_system="terraform",
            connector_id=self.manifest.connector_id,
            connector_version=self.manifest.version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
        )
        artifacts.append(dep_artifact)

        receipt = self._produce_receipt(
            artifacts=artifacts,
            tenant_id=tenant_id,
            actor_id=actor_id,
            correlation_id=correlation_id,
            start_time=start,
            errors=errors,
        )
        return artifacts, receipt

    def _extract_resources(self, tf_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        resources: List[Dict[str, Any]] = []
        modules = tf_state.get("resources", [])
        for mod in modules:
            for instance in mod.get("instances", []):
                resources.append(
                    {
                        "id": f"tf:{mod.get('module', 'root')}:{mod.get('type', 'unk')}:{mod.get('name', 'unk')}",
                        "type": mod.get("type", "unknown"),
                        "name": mod.get("name", "unknown"),
                        "module": mod.get("module", "root"),
                        "mode": mod.get("mode", "managed"),
                        "provider": mod.get("provider", ""),
                        "attributes": instance.get("attributes", {}),
                    }
                )
        return resources

    def _extract_dependencies(self, tf_state: Dict[str, Any]) -> List[Dict[str, Any]]:
        deps: List[Dict[str, Any]] = []
        modules = tf_state.get("resources", [])
        for mod in modules:
            dep_list = mod.get("depends_on", [])
            src = f"tf:{mod.get('module', 'root')}:{mod.get('type', 'unk')}:{mod.get('name', 'unk')}"
            for dep in dep_list:
                deps.append({"from": src, "to": str(dep), "relation": "depends_on"})
        return deps
