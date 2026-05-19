"""AWS IAM Connector — read-only ingestion of IAM identity graph.

Deterministic connector that normalizes AWS IAM policies, roles, users, groups
into IdentityGraphArtifact.
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


class AWSIAMConnector(BaseConnectorWorker):
    """Ingest AWS IAM identity data deterministically."""

    MANIFEST = ConnectorManifest(
        connector_id="connector.aws_iam.v1",
        name="AWS IAM Connector",
        version="1.0.0",
        description="Ingests AWS IAM identity and policy data into semantic artifacts",
        capability_classes=(
            ConnectorCapabilityClass.IDENTITY_READ,
            ConnectorCapabilityClass.SECURITY_READ,
        ),
        sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
        target_systems=("aws",),
        output_schemas=("IdentityGraphArtifact",),
        required_credentials=("aws_access_key_id", "aws_secret_access_key"),
        config_schema={
            "type": "object",
            "properties": {
                "region": {"type": "string"},
                "account_id": {"type": "string"},
            },
            "required": ["account_id"],
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

        raw_iam = kwargs.get("raw_state", self.config.get("raw_state", {}))
        identities = self._extract_identities(raw_iam)
        relationships = self._extract_relationships(raw_iam)

        artifact = ArtifactNormalizer.normalize_identity_graph(
            identities=identities,
            relationships=relationships,
            source_system="aws_iam",
            connector_id=self.manifest.connector_id,
            connector_version=self.manifest.version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
        )
        artifacts.append(artifact)

        receipt = self._produce_receipt(
            artifacts=artifacts, tenant_id=tenant_id, actor_id=actor_id,
            correlation_id=correlation_id, start_time=start, errors=errors,
        )
        return artifacts, receipt

    def _extract_identities(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        identities: List[Dict[str, Any]] = []
        for role in raw.get("roles", []):
            identities.append({"arn": role.get("Arn", ""), "type": "role", "name": role.get("RoleName", ""), "path": role.get("Path", "/")})
        for user in raw.get("users", []):
            identities.append({"arn": user.get("Arn", ""), "type": "user", "name": user.get("UserName", ""), "path": user.get("Path", "/")})
        for group in raw.get("groups", []):
            identities.append({"arn": group.get("Arn", ""), "type": "group", "name": group.get("GroupName", ""), "path": group.get("Path", "/")})
        return identities

    def _extract_relationships(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        rels: List[Dict[str, Any]] = []
        for role in raw.get("roles", []):
            role_arn = role.get("Arn", "")
            for policy in role.get("AttachedPolicies", []):
                rels.append({"from": role_arn, "to": policy.get("PolicyArn", ""), "relation": "attached_policy"})
        for user in raw.get("users", []):
            user_arn = user.get("Arn", "")
            for group in user.get("Groups", []):
                rels.append({"from": user_arn, "to": group.get("Arn", ""), "relation": "member_of"})
        return rels
