"""OpenTelemetry Connector — read-only ingestion of trace/span data.

Deterministic connector that normalizes OTel trace data into canonical
TraceTopologyArtifact.
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


class OpenTelemetryConnector(BaseConnectorWorker):
    """Ingest OpenTelemetry trace/span data deterministically."""

    MANIFEST = ConnectorManifest(
        connector_id="connector.opentelemetry.v1",
        name="OpenTelemetry Trace Connector",
        version="1.0.0",
        description="Ingests OpenTelemetry trace data into semantic artifacts",
        capability_classes=(
            ConnectorCapabilityClass.TRACE_READ,
            ConnectorCapabilityClass.METRIC_READ,
        ),
        sandbox_policy=ConnectorSandboxPolicy.READ_ONLY,
        target_systems=("opentelemetry", "jaeger", "zipkin", "tempo"),
        output_schemas=("TraceTopologyArtifact",),
        required_credentials=(),
        config_schema={
            "type": "object",
            "properties": {
                "service_name_filter": {"type": "array", "items": {"type": "string"}},
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

        raw_trace = kwargs.get("raw_state", self.config.get("raw_state", {}))
        spans = raw_trace.get("spans", [])

        artifact = ArtifactNormalizer.normalize_trace_topology(
            spans=spans,
            source_system="opentelemetry",
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
