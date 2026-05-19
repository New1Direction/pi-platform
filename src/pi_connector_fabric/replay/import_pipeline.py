"""Digital Twin Import + Replay Pipeline.

Extends the existing replay engine to support:
- Historical infrastructure import from connector artifacts
- Replay-safe topology reconstruction
- Cross-system drift analysis
- Temporal dependency replay
- Governed incident reconstruction

All replay operations are read-only. No mutation of real systems.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pi_connector_fabric.sdk.core import NormalizedArtifact, IngestionReceipt
from pi_connector_fabric.topology.engine import (
    CrossSystemDependencyGraph,
    RiskPropagationTopology,
    TopologyEdge,
    TopologyNode,
    UnifiedTopologyGraph,
)


class DigitalTwinImport:
    """Deterministic importer for connector artifacts into digital twin state.

    Reconstructs a topology graph from historical connector receipts.
    All operations are read-only and replay-safe.
    """

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self._artifacts: Dict[str, NormalizedArtifact] = {}
        self._receipts: Dict[str, IngestionReceipt] = {}
        self._topology = UnifiedTopologyGraph(tenant_id=tenant_id, correlation_id="import")
        self._cross_system = CrossSystemDependencyGraph(tenant_id=tenant_id)

    def import_artifact(self, artifact: NormalizedArtifact) -> TopologyNode:
        """Import a single artifact into the digital twin."""
        self._artifacts[artifact.artifact_hash] = artifact
        self._cross_system.register_artifact(artifact)
        nodes = self._topology.add_artifact(artifact)
        return nodes[0] if nodes else TopologyNode(
            node_id=artifact.artifact_id,
            node_type=artifact.artifact_family,
            system=artifact.source_system,
            tenant_id=self.tenant_id,
            artifact_hash=artifact.artifact_hash,
        )

    def import_receipt(self, receipt: IngestionReceipt) -> None:
        """Import an ingestion receipt as provenance."""
        self._receipts[receipt.receipt_id] = receipt

    def build_cross_system_links(self, rules: List[Dict[str, str]]) -> None:
        """Apply cross-system linking rules deterministically."""
        for rule in rules:
            self._cross_system.add_link_rule(
                from_system=rule["from_system"],
                to_system=rule["to_system"],
                from_field=rule["from_field"],
                to_field=rule["to_field"],
                relation=rule["relation"],
            )
        # Add resulting edges to topology
        for edge in self._cross_system.to_topology_edges():
            self._topology.add_cross_system_link(
                from_node=edge.from_node,
                to_node=edge.to_node,
                relation=edge.relation,
                provenance="cross_system_engine",
            )

    def snapshot_topology(self) -> Dict[str, Any]:
        """Produce deterministic snapshot of current topology."""
        return {
            "tenant_id": self.tenant_id,
            "node_count": len(self._topology._nodes),
            "edge_count": len(self._topology._edges),
            "graph_hash": self._topology.graph_hash(),
            "systems": sorted(set(n.system for n in self._topology._nodes.values())),
            "artifact_count": len(self._artifacts),
            "receipt_count": len(self._receipts),
            "snapshot_at": datetime.now(timezone.utc).isoformat(),
        }

    def drift_analysis(
        self,
        previous_topology: UnifiedTopologyGraph,
    ) -> Dict[str, Any]:
        """Compute deterministic drift between two topology snapshots.

        Returns structured diff: added nodes, removed nodes, added edges, removed edges.
        """
        current_nodes = {n.node_id for n in self._topology.get_nodes()}
        previous_nodes = {n.node_id for n in previous_topology.get_nodes()}

        added_nodes = sorted(current_nodes - previous_nodes)
        removed_nodes = sorted(previous_nodes - current_nodes)

        current_edges = {e.edge_id for e in self._topology.get_edges()}
        previous_edges = {e.edge_id for e in previous_topology.get_edges()}

        added_edges = sorted(current_edges - previous_edges)
        removed_edges = sorted(previous_edges - current_edges)

        drift_data = {
            "added_nodes": added_nodes,
            "removed_nodes": removed_nodes,
            "added_edges": added_edges,
            "removed_edges": removed_edges,
            "node_delta": len(added_nodes) - len(removed_nodes),
            "edge_delta": len(added_edges) - len(removed_edges),
            "stable": len(added_nodes) == 0 and len(removed_nodes) == 0 and len(added_edges) == 0 and len(removed_edges) == 0,
            "drift_hash": hashlib.sha256(
                json.dumps({
                    "added_nodes": added_nodes,
                    "removed_nodes": removed_nodes,
                    "added_edges": added_edges,
                    "removed_edges": removed_edges,
                }, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
        return drift_data

    def incident_reconstruction(
        self,
        origin_node: str,
        max_hops: int = 5,
    ) -> Dict[str, Any]:
        """Reconstruct incident blast radius from a topology node.

        Returns all affected nodes within blast radius.
        """
        risk = RiskPropagationTopology(self._topology)
        blast = risk.blast_radius(origin_node, max_hops)
        return {
            "origin": origin_node,
            "tenant_id": self.tenant_id,
            "blast_radius": blast,
            "affected_systems": sorted(set(
                self._topology.get_node(n).system
                for n in blast["reachable_nodes"]
                if self._topology.get_node(n)
            )),
            "reconstruction_at": datetime.now(timezone.utc).isoformat(),
        }

    def temporal_replay(
        self,
        receipts: List[IngestionReceipt],
        build_steps: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Replay historical ingestion receipts to reconstruct state evolution.

        Read-only. Reconstructs what the twin looked like at each step.
        """
        snapshots: List[Dict[str, Any]] = []
        for i, receipt in enumerate(receipts):
            # Rebuild state up to this receipt
            step_artifacts = [
                self._artifacts[h] for h in receipt.artifact_hashes if h in self._artifacts
            ]
            step_topology = UnifiedTopologyGraph(
                tenant_id=self.tenant_id,
                correlation_id=f"replay_{i}",
            )
            for artifact in step_artifacts:
                step_topology.add_artifact(artifact)

            snapshots.append({
                "step": i,
                "receipt_id": receipt.receipt_id,
                "artifact_count": len(step_artifacts),
                "node_count": len(step_topology._nodes),
                "edge_count": len(step_topology._edges),
                "graph_hash": step_topology.graph_hash(),
            })

        return {
            "steps": len(snapshots),
            "snapshots": snapshots,
            "final_node_count": len(self._topology._nodes),
            "final_edge_count": len(self._topology._edges),
            "replay_hash": hashlib.sha256(
                json.dumps([s["graph_hash"] for s in snapshots], sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
        }
