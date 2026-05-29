"""GitHub Actions Connector — read-only ingestion of CI/CD pipeline state.

Deterministic connector that normalizes GitHub Actions workflow runs,
jobs, and deployments into DeploymentLineageArtifact.
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


class GitHubActionsConnector(BaseConnectorWorker):
    """Ingest GitHub Actions workflow data deterministically."""

    MANIFEST = ConnectorManifest(
        connector_id="connector.github_actions.v1",
        name="GitHub Actions Connector",
        version="1.0.0",
        description="Ingests GitHub Actions workflow and deployment data",
        capability_classes=(
            ConnectorCapabilityClass.LINEAGE_READ,
            ConnectorCapabilityClass.EVENT_READ,
        ),
        sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
        target_systems=("github",),
        output_schemas=("DeploymentLineageArtifact",),
        required_credentials=("github_token",),
        config_schema={
            "type": "object",
            "properties": {
                "owner": {"type": "string"},
                "repo": {"type": "string"},
            },
            "required": ["owner", "repo"],
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
        deployments = self._extract_deployments(raw)

        artifact = ArtifactNormalizer.normalize_deployment_lineage(
            deployments=deployments,
            source_system="github_actions",
            connector_id=self.manifest.connector_id,
            connector_version=self.manifest.version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
        )
        artifacts.append(artifact)

        receipt = self._produce_receipt(
            artifacts=artifacts,
            tenant_id=tenant_id,
            actor_id=actor_id,
            correlation_id=correlation_id,
            start_time=start,
            errors=errors,
        )
        return artifacts, receipt

    def _extract_deployments(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        deployments: List[Dict[str, Any]] = []
        for run in raw.get("workflow_runs", []):
            deployments.append(
                {
                    "id": str(run.get("id", "")),
                    "name": run.get("name", ""),
                    "workflow": run.get("path", ""),
                    "branch": run.get("head_branch", ""),
                    "commit": run.get("head_sha", ""),
                    "status": run.get("status", ""),
                    "conclusion": run.get("conclusion", ""),
                    "created_at": run.get("created_at", ""),
                    "updated_at": run.get("updated_at", ""),
                }
            )
        return deployments
