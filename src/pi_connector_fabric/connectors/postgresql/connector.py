"""PostgreSQL Schema Topology Connector — read-only ingestion of database schema.

Deterministic connector that normalizes PostgreSQL schema, tables, columns,
constraints, indexes into InfrastructureStateArtifact + DependencyGraphArtifact.
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


class PostgreSQLConnector(BaseConnectorWorker):
    """Ingest PostgreSQL schema topology deterministically."""

    MANIFEST = ConnectorManifest(
        connector_id="connector.postgresql.v1",
        name="PostgreSQL Schema Connector",
        version="1.0.0",
        description="Ingests PostgreSQL schema topology into semantic artifacts",
        capability_classes=(
            ConnectorCapabilityClass.STATE_READ,
            ConnectorCapabilityClass.DEPENDENCY_READ,
        ),
        sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
        target_systems=("postgresql", "postgres", "cockroachdb", "crdb"),
        output_schemas=("InfrastructureStateArtifact", "DependencyGraphArtifact"),
        required_credentials=("db_user", "db_password"),
        config_schema={
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "database": {"type": "string"},
                "sslmode": {"type": "string"},
            },
            "required": ["host", "database"],
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
        tables = raw.get("tables", [])

        # Schema topology as dependency graph (foreign key relations)
        dependencies = []
        for table in tables:
            for fk in table.get("foreign_keys", []):
                dependencies.append(
                    {
                        "from": f"pg:{table.get('schema', 'public')}.{table.get('name', 'unk')}",
                        "to": f"pg:{fk.get('ref_schema', 'public')}.{fk.get('ref_table', 'unk')}",
                        "relation": "foreign_key",
                        "columns": fk.get("columns", []),
                    }
                )

        dep = ArtifactNormalizer.normalize_dependency_graph(
            dependencies=dependencies,
            source_system="postgresql",
            connector_id=self.manifest.connector_id,
            connector_version=self.manifest.version,
            tenant_id=tenant_id,
            correlation_id=correlation_id,
        )
        artifacts.append(dep)

        # Infrastructure state: all schema objects
        resources = []
        for table in tables:
            resources.append(
                {
                    "id": f"pg:{table.get('schema', 'public')}.{table.get('name', 'unk')}",
                    "type": "table",
                    "schema": table.get("schema", "public"),
                    "name": table.get("name", ""),
                    "columns": table.get("columns", []),
                    "primary_key": table.get("primary_key", []),
                    "indexes": table.get("indexes", []),
                }
            )

        state = ArtifactNormalizer.normalize_infrastructure_state(
            resources=resources,
            source_system="postgresql",
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
