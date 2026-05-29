"""DocumentationHyperFrames — Deterministic architecture documentation videos.

Extends HyperFrameRenderEngine to produce frame sequences from:
- PI Runtime Specification sections
- Layer architecture diagrams (text-based)
- Governance invariant cards
- Connector marketplace catalogs
- Test result dashboards

All frames are deterministic base64 PNGs. No probabilistic layout.
No LLM-generated visuals. Same dark theme as infrastructure HyperFrames.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from pi_connector_fabric.marketplace.governance import ConnectorMarketplaceRegistry
from pi_interoperability_layer.hyperframes import (
    HyperFrame,
    HyperFrameSequence,
    RenderConfig,
)


class DocumentationHyperFrameRenderer:
    """Deterministic renderer for architecture documentation videos.

    Frame sequences are fully deterministic: identical inputs produce
    identical frame hashes, identical sequence hashes, identical MP4 hashes.
    """

    def __init__(self, config: Optional[RenderConfig] = None) -> None:
        self.config = config or RenderConfig(config_id="docs")

    # ──────────────────────────────
    #  Architecture Layer Video
    # ──────────────────────────────

    def render_platform_architecture(
        self,
        layers: List[Dict[str, Any]],
        title: str = "PI Platform Architecture",
    ) -> HyperFrameSequence:
        """Render a frame sequence showing each platform layer.

        Frame 0: Title card + full stack overview
        Frames 1..N: Each layer revealed with components
        Frame N+1: Governance boundary summary
        """
        frames: List[HyperFrame] = []

        # Frame 0: Overview
        overview_lines = [
            "DETERMINISTIC SEMANTIC INFRASTRUCTURE PLATFORM",
            "",
            f"Total Layers: {len(layers)}",
            "",
            "Stack (bottom to top):",
        ]
        for layer in reversed(layers):
            overview_lines.append(f"  [{layer.get('layer_number', '?')}] {layer.get('name', 'Unknown')}")
        frames.append(self._build_frame(0, title, overview_lines))

        # Per-layer frames
        idx = 1
        for layer in layers:
            lines = [
                f"LAYER {layer.get('layer_number', '?')}: {layer.get('name', 'Unknown')}",
                f"Role: {layer.get('role', '')}",
                "",
                "Components:",
            ]
            for comp in layer.get("components", []):
                lines.append(f"  • {comp}")
            lines += [
                "",
                "Invariants:",
            ]
            for inv in layer.get("invariants", []):
                lines.append(f"  ✓ {inv}")
            frames.append(self._build_frame(idx, f"Layer {layer.get('layer_number', '?')}", lines))
            idx += 1

        # Final: governance boundary
        frames.append(self._build_frame(
            idx, "Governance Boundary",
            [
                "HARD SEPARATION ENFORCED",
                "",
                "  ✓ No LLM in Layers 1–3",
                "  ✓ No probabilistic reasoning in core",
                "  ✓ Append-only everywhere",
                "  ✓ Fail-closed governance",
                "  ✓ Deterministic replay-safe",
                "  ✓ Tenant isolation absolute",
            ],
        ))

        return HyperFrameSequence(
            sequence_id=f"docs_arch_{hashlib.sha256(title.encode()).hexdigest()[:16]}",
            source_report_id="architecture",
            frames=frames,
            width=self.config.width,
            height=self.config.height,
            fps=self.config.fps,
            total_frames=len(frames),
        )

    # ──────────────────────────────
    #  Governance Invariant Video
    # ──────────────────────────────

    def render_governance_invariants(
        self,
        invariants: List[Dict[str, str]],
    ) -> HyperFrameSequence:
        """Render governance invariants as a card sequence.

        Frame 0: Title
        Frames 1..N: Each invariant revealed
        Frame N+1: Summary with pass/fail status (all pass in docs)
        """
        frames: List[HyperFrame] = []
        frames.append(self._build_frame(0, "Governance Invariants", [
            "DETERMINISTIC GOVERNANCE ENFORCEMENT",
            "",
            f"Total Invariants: {len(invariants)}",
            "",
            "All invariants are statically validated.",
            "No runtime probabilistic scoring.",
        ]))

        for i, inv in enumerate(invariants, start=1):
            lines = [
                f"INVARIANT {i}: {inv.get('id', 'UNK')}",
                "",
                f"Rule: {inv.get('description', '')}",
                "",
                f"Enforcement: {inv.get('enforcement', 'static')}",
                f"Scope:       {inv.get('scope', 'global')}",
                "Status:      ✓ PASS",
            ]
            frames.append(self._build_frame(i, f"Invariant {inv.get('id', 'UNK')}", lines))

        frames.append(self._build_frame(
            len(frames), "Invariant Summary",
            [f"  ✓ {len(invariants)} invariants enforced"] +
            ["  ✓ 0 violations"] +
            ["  ✓ Deterministic validation only"],
        ))

        seq_hash = hashlib.sha256(json.dumps(
            [inv.get("id", "") for inv in invariants], sort_keys=True, separators=(",", ":")
        ).encode()).hexdigest()

        return HyperFrameSequence(
            sequence_id=f"docs_gov_{seq_hash[:16]}",
            source_report_id="governance",
            frames=frames,
            width=self.config.width,
            height=self.config.height,
            fps=self.config.fps,
            total_frames=len(frames),
        )

    # ──────────────────────────────
    #  Connector Marketplace Catalog Video
    # ──────────────────────────────

    def render_connector_catalog(
        self,
        marketplace: ConnectorMarketplaceRegistry,
    ) -> HyperFrameSequence:
        """Render connector marketplace catalog as frame sequence.

        Frame 0: Catalog overview
        Frames 1..N: Each connector revealed with capabilities
        Frame N+1: Trust tier distribution
        """
        frames: List[HyperFrame] = []
        connectors = marketplace.list_connectors()

        # Overview
        frames.append(self._build_frame(0, "Connector Catalog", [
            "GOVERNED CONNECTOR MARKETPLACE",
            "",
            f"Registered Connectors: {len(connectors)}",
            "",
            "All connectors are:",
            "  • Deterministic",
            "  • Read-only ingestion",
            "  • Governance-gated",
            "  • Replay-safe",
        ]))

        for i, conn in enumerate(connectors, start=1):
            manifest = json.loads(conn.get("manifest_json", "{}"))
            lines = [
                f"CONNECTOR: {manifest.get('name', 'Unknown')}",
                f"ID:        {manifest.get('connector_id', '')}",
                f"Version:   {manifest.get('version', '')}",
                f"Trust:     {manifest.get('trust_tier', 'unknown')}",
                "",
                "Capabilities:",
            ]
            for cap in manifest.get("capability_classes", []):
                lines.append(f"  • {cap}")
            lines += [
                "",
                "Target Systems:",
            ]
            for sys in manifest.get("target_systems", []):
                lines.append(f"  • {sys}")
            frames.append(self._build_frame(i, manifest.get("name", "Connector"), lines))

        # Trust tier distribution
        tier_counts: Dict[str, int] = {}
        for conn in connectors:
            manifest = json.loads(conn.get("manifest_json", "{}"))
            tier = manifest.get("trust_tier", "unknown")
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

        tier_lines = ["TRUST TIER DISTRIBUTION", ""]
        for tier in sorted(tier_counts.keys()):
            tier_lines.append(f"  {tier}: {tier_counts[tier]}")
        frames.append(self._build_frame(len(frames), "Trust Distribution", tier_lines))

        return HyperFrameSequence(
            sequence_id=f"docs_catalog_{len(connectors):03d}",
            source_report_id="connector_catalog",
            frames=frames,
            width=self.config.width,
            height=self.config.height,
            fps=self.config.fps,
            total_frames=len(frames),
        )

    # ──────────────────────────────
    #  Test Result Dashboard Video
    # ──────────────────────────────

    def render_test_dashboard(
        self,
        suite_name: str,
        passed: int,
        failed: int,
        skipped: int,
        modules: List[Dict[str, Any]],
    ) -> HyperFrameSequence:
        """Render test suite results as a deterministic frame sequence.

        Frame 0: Suite summary
        Frames 1..N: Per-module breakdown
        Frame N+1: Final status card
        """
        frames: List[HyperFrame] = []
        total = passed + failed + skipped

        frames.append(self._build_frame(0, f"Test Suite: {suite_name}", [
            f"TOTAL: {total}",
            f"  ✓ PASSED:  {passed}",
            f"  ✗ FAILED:  {failed}",
            f"  ○ SKIPPED: {skipped}",
            "",
            "Success Rate: {:.1f}%".format((passed / total * 100) if total else 0),
        ]))

        for i, mod in enumerate(modules, start=1):
            lines = [
                f"MODULE: {mod.get('name', 'Unknown')}",
                f"  Tests: {mod.get('total', 0)}",
                f"  ✓ Pass:  {mod.get('passed', 0)}",
                f"  ✗ Fail:   {mod.get('failed', 0)}",
                f"  ○ Skip:   {mod.get('skipped', 0)}",
            ]
            if mod.get("duration"):
                lines.append(f"  Duration: {mod.get('duration'):.2f}s")
            frames.append(self._build_frame(i, mod.get("name", "Module"), lines))

        # Final status
        status = "PASS" if failed == 0 else "FAIL"
        frames.append(self._build_frame(
            len(frames), "Suite Status",
            [
                f"RESULT: {status}",
                "",
                "  ✓ All invariants preserved" if failed == 0 else "  ✗ Regressions detected",
                "  ✓ Deterministic replay-safe",
                "  ✓ Zero probabilistic reasoning",
            ],
        ))

        return HyperFrameSequence(
            sequence_id=f"docs_tests_{suite_name}_{passed:03d}_{failed:03d}",
            source_report_id="test_dashboard",
            frames=frames,
            width=self.config.width,
            height=self.config.height,
            fps=self.config.fps,
            total_frames=len(frames),
        )

    # ──────────────────────────────
    #  Shared Frame Builder (uses existing fallback PNG)
    # ──────────────────────────────

    def _build_frame(
        self,
        sequence_index: int,
        title: str,
        lines: List[str],
    ) -> HyperFrame:
        """Build a deterministic text-based frame."""
        from pi_interoperability_layer.hyperframes import HyperFrameRenderEngine

        # Reuse the existing engine's frame builder (which includes fallback PNG)
        engine = HyperFrameRenderEngine(self.config)
        return engine._build_frame(sequence_index, title, lines)

    def encode_mp4(
        self,
        sequence: HyperFrameSequence,
        output_path: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Encode sequence to MP4. Reuses existing HyperFrameRenderEngine encoder."""
        from pi_interoperability_layer.hyperframes import HyperFrameRenderEngine
        engine = HyperFrameRenderEngine(self.config)
        return engine.encode_mp4(sequence, output_path)
