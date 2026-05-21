"""InfrastructureReplayHyperFrames — Deterministic infrastructure replay videos.

Extends HyperFrameRenderEngine to produce frame sequences from real
connector ingestion, topology construction, drift analysis, and governance
audit trails.

All deterministic. No probabilistic layout. Dark theme. Base64 PNG frames.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from pi_connector_fabric.replay.import_pipeline import DigitalTwinImport
from pi_connector_fabric.sdk.core import IngestionReceipt
from pi_connector_fabric.topology.engine import (
    RiskPropagationTopology,
    UnifiedTopologyGraph,
)
from pi_event_fabric.governance.compiler import GovernanceDecision
from pi_interoperability_layer.hyperframes import (
    HyperFrame,
    HyperFrameSequence,
    RenderConfig,
)


class InfrastructureReplayHyperFrameRenderer:
    """Deterministic renderer for infrastructure replay videos.

    Turns real connector data, topology graphs, drift analysis, and
    governance decisions into deterministic frame sequences.
    """

    def __init__(self, config: Optional[RenderConfig] = None) -> None:
        self.config = config or RenderConfig(config_id="infra")

    # ──────────────────────────────
    #  Connector Ingestion Replay
    # ──────────────────────────────

    def render_connector_ingestion(
        self,
        receipts: List[IngestionReceipt],
    ) -> HyperFrameSequence:
        """Render connector ingestion receipts as a timeline video.

        Frame 0: Session overview
        Frames 1..N: Each receipt revealed with artifacts produced
        Frame N+1: Aggregate metrics
        """
        frames: List[HyperFrame] = []

        # Overview
        frames.append(self._build_frame(0, "Connector Ingestion Session", [
            "DETERMINISTIC INFRASTRUCTURE INGESTION",
            "",
            f"Total Receipts: {len(receipts)}",
            f"Total Artifacts: {sum(r.artifact_count for r in receipts)}",
            f"Connectors: {len({r.connector_id for r in receipts})}",
            "",
            "All ingestion is read-only.",
            "All artifacts are immutable.",
        ]))

        for i, receipt in enumerate(receipts, start=1):
            lines = [
                f"RECEIPT: {receipt.receipt_id}",
                f"Connector:  {receipt.connector_id} v{receipt.connector_version}",
                f"Tenant:     {receipt.tenant_id}",
                f"Actor:      {receipt.actor_id}",
                f"Artifacts:  {receipt.artifact_count}",
                f"Fence:      {receipt.fence_used.value}",
                f"Verified:   {'✓' if receipt.verify() else '✗'}",
            ]
            if receipt.error_count > 0:
                lines.append(f"Errors:     {receipt.error_count}")
            lines += [
                "",
                "Artifact Hashes:",
            ]
            for h in receipt.artifact_hashes[:5]:
                lines.append(f"  {h[:24]}...")
            if len(receipt.artifact_hashes) > 5:
                lines.append(f"  ... and {len(receipt.artifact_hashes) - 5} more")
            frames.append(self._build_frame(i, receipt.receipt_id, lines))

        # Aggregate
        total_artifacts = sum(r.artifact_count for r in receipts)
        total_errors = sum(r.error_count for r in receipts)
        frames.append(self._build_frame(len(frames), "Ingestion Summary", [
            "SESSION SUMMARY",
            "",
            f"  Receipts:    {len(receipts)}",
            f"  Artifacts:   {total_artifacts}",
            f"  Errors:      {total_errors}",
            f"  Verified:    {len([r for r in receipts if r.verify()])}/{len(receipts)}",
            "",
            "All receipts cryptographically verifiable.",
        ]))

        return HyperFrameSequence(
            sequence_id=f"infra_ingest_{len(receipts):03d}",
            source_report_id="connector_ingestion",
            frames=frames,
            width=self.config.width,
            height=self.config.height,
            fps=self.config.fps,
            total_frames=len(frames),
        )

    # ──────────────────────────────
    #  Topology Construction Replay
    # ──────────────────────────────

    def render_topology_construction(
        self,
        dt_import: DigitalTwinImport,
        max_nodes_display: int = 30,
    ) -> HyperFrameSequence:
        """Render topology graph construction step-by-step.

        Frame 0: Empty graph
        Frames 1..N: Each artifact added, nodes/edges revealed
        Frame N+1: Final graph state with hash
        """
        frames: List[HyperFrame] = []
        artifacts = list(dt_import._artifacts.values())

        # Empty graph
        frames.append(self._build_frame(0, "Topology Construction", [
            "CROSS-SYSTEM TOPOLOGY GRAPH",
            "",
            "Initial state: empty",
            f"Artifacts to ingest: {len(artifacts)}",
            "",
            "Deterministic node placement.",
            "Deterministic edge linking.",
        ]))

        # Build graph incrementally
        running_graph = UnifiedTopologyGraph(dt_import.tenant_id, "construction")
        for i, artifact in enumerate(artifacts, start=1):
            nodes_added = running_graph.add_artifact(artifact)
            lines = [
                f"STEP {i}: {artifact.source_system} artifact",
                f"Family: {artifact.artifact_family}",
                f"Hash:   {artifact.artifact_hash[:24]}...",
                "",
                f"Nodes added: {len(nodes_added)}",
                f"Total nodes: {len(running_graph._nodes)}",
                f"Total edges: {len(running_graph._edges)}",
            ]
            # Show sample nodes
            sample_nodes = list(running_graph.get_nodes())[:max_nodes_display]
            if sample_nodes:
                lines.append("")
                lines.append("Nodes:")
                for n in sample_nodes:
                    lines.append(f"  {n.node_id[:40]} [{n.node_type}]")
            frames.append(self._build_frame(i, f"Step {i}: {artifact.source_system}", lines))

        # Final state
        final_hash = running_graph.graph_hash()
        frames.append(self._build_frame(len(frames), "Final Topology", [
            "CONSTRUCTION COMPLETE",
            "",
            f"Total nodes: {len(running_graph._nodes)}",
            f"Total edges: {len(running_graph._edges)}",
            f"Graph hash:  {final_hash[:32]}...",
            f"Systems:     {', '.join(sorted({n.system for n in running_graph.get_nodes()}))}",
            "",
            "Deterministic. Replay-safe. Tenant-isolated.",
        ]))

        return HyperFrameSequence(
            sequence_id=f"infra_topo_{len(artifacts):03d}_{final_hash[:16]}",
            source_report_id="topology_construction",
            frames=frames,
            width=self.config.width,
            height=self.config.height,
            fps=self.config.fps,
            total_frames=len(frames),
        )

    # ──────────────────────────────
    #  Drift Analysis Replay
    # ──────────────────────────────

    def render_drift_evolution(
        self,
        snapshots: List[Dict[str, Any]],
    ) -> HyperFrameSequence:
        """Render drift analysis across multiple topology snapshots.

        Frame 0: Baseline snapshot
        Frames 1..N-1: Each delta revealed
        Frame N: Final drift assessment
        """
        frames: List[HyperFrame] = []
        if not snapshots:
            return self._empty_sequence("drift_evolution")

        # Baseline
        baseline = snapshots[0]
        frames.append(self._build_frame(0, "Drift Analysis: Baseline", [
            "BASELINE SNAPSHOT",
            "",
            f"Graph hash: {baseline.get('graph_hash', 'N/A')[:32]}...",
            f"Nodes: {baseline.get('node_count', 0)}",
            f"Edges: {baseline.get('edge_count', 0)}",
        ]))

        for i in range(1, len(snapshots)):
            prev = snapshots[i - 1]
            curr = snapshots[i]
            lines = [
                f"STEP {i}: Snapshot Comparison",
                "",
                f"Previous nodes: {prev.get('node_count', 0)}",
                f"Current nodes:  {curr.get('node_count', 0)}",
                f"Previous edges: {prev.get('edge_count', 0)}",
                f"Current edges:  {curr.get('edge_count', 0)}",
                "",
                f"Graph hash: {curr.get('graph_hash', 'N/A')[:32]}...",
            ]
            if curr.get('added_nodes'):
                lines += ["", "Added nodes:"]
                for n in curr.get('added_nodes', [])[:10]:
                    lines.append(f"  + {n}")
            if curr.get('removed_nodes'):
                lines += ["", "Removed nodes:"]
                for n in curr.get('removed_nodes', [])[:10]:
                    lines.append(f"  - {n}")
            if curr.get('stable'):
                lines += ["", "Status: ✓ STABLE (no drift)"]
            else:
                lines += ["", "Status: ⚠ DRIFT DETECTED"]
            frames.append(self._build_frame(i, f"Step {i}", lines))

        # Final assessment
        final = snapshots[-1]
        frames.append(self._build_frame(len(frames), "Drift Assessment", [
            "FINAL ASSESSMENT",
            "",
            f"Total snapshots: {len(snapshots)}",
            f"Stable periods:   {sum(1 for s in snapshots if s.get('stable'))}",
            f"Drift periods:    {sum(1 for s in snapshots if not s.get('stable'))}",
            "",
            f"Final hash: {final.get('graph_hash', 'N/A')[:32]}...",
            "",
            "Drift is deterministic and auditable.",
        ]))

        return HyperFrameSequence(
            sequence_id=f"infra_drift_{len(snapshots):03d}",
            source_report_id="drift_evolution",
            frames=frames,
            width=self.config.width,
            height=self.config.height,
            fps=self.config.fps,
            total_frames=len(frames),
        )

    # ──────────────────────────────
    #  Blast Radius Propagation Replay
    # ──────────────────────────────

    def render_blast_radius_propagation(
        self,
        risk_topology: RiskPropagationTopology,
        origin_node: str,
        max_hops: int = 5,
    ) -> HyperFrameSequence:
        """Render blast radius propagation as an animated frame sequence.

        Frame 0: Origin node highlighted
        Frames 1..max_hops: Each propagation depth revealed
        Frame max_hops+1: Full blast radius + aggregate metrics
        """
        frames: List[HyperFrame] = []
        graph = risk_topology.graph

        # Origin
        frames.append(self._build_frame(0, "Blast Radius: Origin", [
            f"ORIGIN: {origin_node}",
            "",
            "Deterministic BFS propagation.",
            "No probabilistic scoring.",
            f"Max hops: {max_hops}",
        ]))

        # Per-hop reveal
        visited: Dict[str, int] = {origin_node: 0}
        queue = [origin_node]
        head = 0
        hop_revealed: Dict[int, List[str]] = {0: [origin_node]}

        while head < len(queue):
            current = queue[head]
            head += 1
            current_hops = visited[current]
            if current_hops >= max_hops:
                continue
            for neighbor in graph.get_neighbors(current):
                if neighbor not in visited:
                    visited[neighbor] = current_hops + 1
                    queue.append(neighbor)
                    hop_revealed.setdefault(current_hops + 1, []).append(neighbor)

        for hop in range(1, max_hops + 1):
            nodes_at_hop = hop_revealed.get(hop, [])
            lines = [
                f"HOP {hop}: Propagation Depth",
                "",
                f"Nodes reached at this depth: {len(nodes_at_hop)}",
                f"Cumulative reached: {sum(len(hop_revealed.get(h, [])) for h in range(hop + 1)) - 1}",
            ]
            if nodes_at_hop:
                lines.append("")
                lines.append("Nodes:")
                for n in nodes_at_hop[:20]:
                    lines.append(f"  {n}")
                if len(nodes_at_hop) > 20:
                    lines.append(f"  ... and {len(nodes_at_hop) - 20} more")
            frames.append(self._build_frame(hop, f"Hop {hop}", lines))

        # Full blast
        blast = risk_topology.blast_radius(origin_node, max_hops)
        frames.append(self._build_frame(len(frames), "Blast Radius: Complete", [
            "BLAST RADIUS ANALYSIS",
            "",
            f"Origin:        {origin_node}",
            f"Max hops:      {max_hops}",
            f"Total reached: {blast['reachable_count']}",
            "",
            "Hop distribution:",
        ]))
        for h in range(1, max_hops + 1):
            count = blast["hop_distribution"].get(h, 0)
            frames[-1].frame_metadata[f"hop_{h}"] = count
            # Rebuild lines with distribution
        dist_lines = [
            "BLAST RADIUS ANALYSIS",
            "",
            f"Origin:        {origin_node}",
            f"Max hops:      {max_hops}",
            f"Total reached: {blast['reachable_count']}",
            "",
            "Hop distribution:",
        ]
        for h in range(1, max_hops + 1):
            count = blast["hop_distribution"].get(h, 0)
            dist_lines.append(f"  Depth {h}: {count} nodes")
        # Replace last frame
        frames[-1] = self._build_frame(len(frames) - 1, "Blast Radius: Complete", dist_lines)

        return HyperFrameSequence(
            sequence_id=f"infra_blast_{origin_node}_{max_hops}",
            source_report_id="blast_radius",
            frames=frames,
            width=self.config.width,
            height=self.config.height,
            fps=self.config.fps,
            total_frames=len(frames),
        )

    # ──────────────────────────────
    #  Governance Audit Trail Replay
    # ──────────────────────────────

    def render_governance_audit_trail(
        self,
        decisions: List[GovernanceDecision],
    ) -> HyperFrameSequence:
        """Render governance decisions as an audit trail video.

        Frame 0: Audit overview
        Frames 1..N: Each decision revealed
        Frame N+1: Aggregate policy metrics
        """
        frames: List[HyperFrame] = []

        frames.append(self._build_frame(0, "Governance Audit Trail", [
            "DETERMINISTIC GOVERNANCE DECISION LOG",
            "",
            f"Total Decisions: {len(decisions)}",
            f"Allow: {sum(1 for d in decisions if d.effect.value == 'allow')}",
            f"Deny:  {sum(1 for d in decisions if d.effect.value == 'deny')}",
            "",
            "All decisions are deterministic.",
            "All decisions are statically validated.",
            "All decisions are auditable and replay-safe.",
        ]))

        for i, decision in enumerate(decisions, start=1):
            lines = [
                f"DECISION {i}: {decision.decision_id}",
                f"Context:   {decision.context_id}",
                f"Effect:    {decision.effect.value.upper()}",
                f"Rules:     {len(decision.matched_rules)}",
            ]
            if decision.matched_rules:
                lines.append("")
                lines.append("Matched rules:")
                for r in decision.matched_rules:
                    lines.append(f"  • {r}")
            if decision.denied_by:
                lines.append(f"Denied by: {decision.denied_by}")
            frames.append(self._build_frame(i, decision.decision_id, lines))

        # Aggregate
        allow_count = sum(1 for d in decisions if d.effect.value == "allow")
        deny_count = sum(1 for d in decisions if d.effect.value == "deny")
        frames.append(self._build_frame(len(frames), "Audit Summary", [
            "GOVERNANCE AUDIT SUMMARY",
            "",
            f"  Total:    {len(decisions)}",
            f"  Allowed:  {allow_count}",
            f"  Denied:   {deny_count}",
            f"  Pass rate: {(allow_count / len(decisions) * 100):.1f}%" if decisions else "  N/A",
            "",
            "Fail-closed policy enforced.",
            "Zero probabilistic scoring.",
        ]))

        return HyperFrameSequence(
            sequence_id=f"infra_gov_{len(decisions):03d}",
            source_report_id="governance_audit",
            frames=frames,
            width=self.config.width,
            height=self.config.height,
            fps=self.config.fps,
            total_frames=len(frames),
        )

    # ──────────────────────────────
    #  Shared Frame Builder
    # ──────────────────────────────

    def _build_frame(
        self,
        sequence_index: int,
        title: str,
        lines: List[str],
    ) -> HyperFrame:
        from pi_interoperability_layer.hyperframes import HyperFrameRenderEngine
        engine = HyperFrameRenderEngine(self.config)
        return engine._build_frame(sequence_index, title, lines)

    def _empty_sequence(self, report_id: str) -> HyperFrameSequence:
        return HyperFrameSequence(
            sequence_id=f"infra_empty_{report_id}",
            source_report_id=report_id,
            frames=[self._build_frame(0, "Empty", ["No data available"])],
            width=self.config.width,
            height=self.config.height,
            fps=self.config.fps,
            total_frames=1,
        )

    def encode_mp4(
        self,
        sequence: HyperFrameSequence,
        output_path: Optional[str] = None,
    ) -> Tuple[str, str]:
        from pi_interoperability_layer.hyperframes import HyperFrameRenderEngine
        engine = HyperFrameRenderEngine(self.config)
        return engine.encode_mp4(sequence, output_path)
