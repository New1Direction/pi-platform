"""HyperFrames Temporal Rendering Engine.

Deterministic, semantically governed frame sequence generation from
SemanticDriftReport and RiskPropagationGraph.

Produces MP4/GIF with guaranteed deterministic frame composition:
- Identical frame sequence for identical inputs
- Stable ordering, normalized formatting, deterministic encoding
- No LLM inference. No probabilistic visual choices.

Uses matplotlib + Pillow for frame generation; imageio for MP4 encoding.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

from pi_interoperability_layer.drift_propagation import RiskPropagationGraph
from pi_interoperability_layer.workers.pi_observability_diff_worker import (
    SemanticDelta,
    SemanticDriftReport,
)

# ──────────────────────────────
#  Frame Primitives
# ──────────────────────────────


class HyperFrame(BaseModel):
    """A single deterministic frame in the temporal rendering sequence."""

    frame_id: str
    sequence_index: int = Field(..., ge=0)
    # Frame payload: base64 PNG or raw RGB bytes (deterministic)
    frame_data: str = ""  # base64-encoded PNG
    frame_hash: str = ""
    # Metadata for deterministic reconstruction
    frame_metadata: Dict[str, Any] = Field(default_factory=dict)
    model_config = {"frozen": True}

    def model_post_init(self, __context: Any) -> None:
        if not self.frame_hash and self.frame_data:
            object.__setattr__(self, "frame_hash", hashlib.sha256(self.frame_data.encode()).hexdigest())


class HyperFrameSequence(BaseModel):
    """Immutable ordered sequence of HyperFrames with deterministic hash."""

    sequence_id: str
    source_report_id: str
    frames: List[HyperFrame] = Field(default_factory=list)
    # Rendering parameters (frozen at creation)
    width: int = 1280
    height: int = 720
    fps: int = 2
    total_frames: int = 0
    # Deterministic hash of the entire sequence
    sequence_hash: str = ""
    model_config = {"frozen": True}

    def model_post_init(self, __context: Any) -> None:
        if not self.sequence_hash:
            object.__setattr__(self, "sequence_hash", self._compute_hash())

    def _compute_hash(self) -> str:
        payload = {
            "sequence_id": self.sequence_id,
            "source_report_id": self.source_report_id,
            "width": self.width,
            "height": self.height,
            "fps": self.fps,
            "frame_hashes": [f.frame_hash for f in self.frames],
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()


class RenderConfig(BaseModel):
    """Immutable rendering configuration for HyperFrames."""

    config_id: str
    width: int = Field(default=1280, ge=320, le=3840)
    height: int = Field(default=720, ge=240, le=2160)
    fps: int = Field(default=2, ge=1, le=60)
    # Color palette (deterministic hex values)
    color_palette: Dict[str, str] = Field(
        default_factory=lambda: {
            "background": "#0d1117",
            "text": "#c9d1d9",
            "node_safe": "#238636",
            "node_warn": "#d29922",
            "node_risk": "#da3633",
            "node_critical": "#8b0000",
            "edge_normal": "#30363d",
            "edge_drift": "#f78166",
            "delta_add": "#238636",
            "delta_remove": "#da3633",
            "delta_change": "#d29922",
        }
    )
    # Font settings (deterministic)
    font_family: str = "monospace"
    font_size: int = 12
    # Layout determinism seed (not random — derived from input hash)
    layout_seed: str = ""
    model_config = {"frozen": True}


# ──────────────────────────────
#  Rendering Engine
# ──────────────────────────────


class HyperFrameRenderEngine:
    """Deterministic temporal rendering engine.

    Generates frame sequences from drift reports and risk graphs.
    All visual decisions are rule-based, not probabilistic.
    """

    def __init__(self, config: Optional[RenderConfig] = None) -> None:
        self.config = config or RenderConfig(config_id="default")

    def render_drift_report(
        self,
        report: SemanticDriftReport,
    ) -> HyperFrameSequence:
        """Render a deterministic frame sequence from a SemanticDriftReport.

        Frame 0: Baseline state (no deltas highlighted)
        Frames 1..N: Each delta type group revealed sequentially
        Frame N+1: Final aggregate view with all deltas and scores
        """
        frames: List[HyperFrame] = []

        # Frame 0: Baseline — summary card with baseline + modified IDs
        frames.append(
            self._build_frame(
                sequence_index=0,
                title="Drift Analysis: Baseline",
                lines=self._format_baseline(report),
            )
        )

        # Group deltas by type for sequential reveal
        type_groups: Dict[str, List[SemanticDelta]] = {}
        for d in report.deltas:
            type_groups.setdefault(d.delta_type.value, []).append(d)

        idx = 1
        for delta_type in sorted(type_groups.keys()):
            group = type_groups[delta_type]
            frames.append(
                self._build_frame(
                    sequence_index=idx,
                    title=f"Delta Group: {delta_type}",
                    lines=self._format_delta_group(delta_type, group),
                )
            )
            idx += 1

        # Final frame: aggregate scores
        frames.append(
            self._build_frame(
                sequence_index=idx,
                title="Drift Analysis: Aggregate",
                lines=self._format_aggregate(report),
            )
        )

        seq_id = f"hyper_{report.report_id}"
        return HyperFrameSequence(
            sequence_id=seq_id,
            source_report_id=report.report_id,
            frames=frames,
            width=self.config.width,
            height=self.config.height,
            fps=self.config.fps,
            total_frames=len(frames),
        )

    def render_risk_graph(
        self,
        risk_graph: RiskPropagationGraph,
    ) -> HyperFrameSequence:
        """Render a deterministic frame sequence from a RiskPropagationGraph.

        Frame 0: Topology overview (all nodes, no risk colors)
        Frame 1: Direct blast radius highlighted
        Frame 2: First propagation depth highlighted
        Frame 3: Full propagation depth + critical/high nodes
        Frame 4: Aggregate metrics panel
        """
        frames: List[HyperFrame] = []

        # Frame 0: Topology overview
        frames.append(
            self._build_frame(
                sequence_index=0,
                title="Risk Propagation: Topology Overview",
                lines=self._format_topology_overview(risk_graph),
            )
        )

        # Frame 1: Direct blast radius
        frames.append(
            self._build_frame(
                sequence_index=1,
                title="Risk Propagation: Direct Blast Radius",
                lines=self._format_direct_blast(risk_graph),
            )
        )

        # Frame 2: Propagation depth view
        frames.append(
            self._build_frame(
                sequence_index=2,
                title="Risk Propagation: Propagation Depth",
                lines=self._format_propagation_depth(risk_graph),
            )
        )

        # Frame 3: Full risk map
        frames.append(
            self._build_frame(
                sequence_index=3,
                title="Risk Propagation: Full Risk Map",
                lines=self._format_full_risk(risk_graph),
            )
        )

        # Frame 4: Aggregate metrics
        frames.append(
            self._build_frame(
                sequence_index=4,
                title="Risk Propagation: Aggregate Metrics",
                lines=self._format_risk_aggregate(risk_graph),
            )
        )

        seq_id = f"hyper_risk_{risk_graph.graph_id}"
        return HyperFrameSequence(
            sequence_id=seq_id,
            source_report_id=risk_graph.drift_report_id,
            frames=frames,
            width=self.config.width,
            height=self.config.height,
            fps=self.config.fps,
            total_frames=len(frames),
        )

    def encode_mp4(
        self,
        sequence: HyperFrameSequence,
        output_path: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Encode a HyperFrameSequence to MP4.

        Returns (output_path, file_hash). Requires imageio-ffmpeg.
        """
        try:
            import imageio.v3 as iio
            import numpy as np
            from PIL import Image
        except ImportError as exc:
            raise RuntimeError(
                "HyperFrames MP4 encoding requires imageio and Pillow. Install: pip install imageio[ffmpeg] Pillow"
            ) from exc

        # Decode base64 frames to numpy arrays (deterministic)
        import base64

        frames_np: List[Any] = []
        for frame in sequence.frames:
            if not frame.frame_data:
                continue
            img_bytes = base64.b64decode(frame.frame_data)
            img = Image.open(io.BytesIO(img_bytes)).convert("RGB")
            frames_np.append(np.array(img))

        if not frames_np:
            raise ValueError("No valid frames to encode")

        out_path = output_path or f"/tmp/{sequence.sequence_id}.mp4"
        # Deterministic encoding: fixed quality, no randomness
        # Use v2 API for ffmpeg compatibility
        import imageio

        writer = imageio.get_writer(out_path, fps=sequence.fps, codec="libx264", quality=8)
        for frame_np in frames_np:
            writer.append_data(frame_np)
        writer.close()

        # Hash the output file for determinism verification
        with open(out_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        return (out_path, file_hash)

    # ------------------------------------------------------------------
    # Frame builders (deterministic text-based frames — stable for tests)
    # ------------------------------------------------------------------

    def _build_frame(
        self,
        sequence_index: int,
        title: str,
        lines: List[str],
    ) -> HyperFrame:
        """Build a deterministic text-based frame as base64 PNG.

        Uses matplotlib when available; falls back to stdlib PNG generator.
        No probabilistic layout. No external dependency required for tests.
        """
        try:
            import matplotlib

            matplotlib.use("Agg")
            import matplotlib.pyplot as plt

            fig, ax = plt.subplots(figsize=(self.config.width / 100, self.config.height / 100), dpi=100)
            ax.set_facecolor(self.config.color_palette["background"])
            fig.patch.set_facecolor(self.config.color_palette["background"])
            ax.axis("off")

            ax.text(
                0.5,
                0.96,
                title,
                transform=ax.transAxes,
                fontsize=self.config.font_size + 4,
                fontfamily=self.config.font_family,
                color=self.config.color_palette["text"],
                ha="center",
                va="top",
                fontweight="bold",
            )

            body = "\n".join(lines)
            ax.text(
                0.05,
                0.90,
                body,
                transform=ax.transAxes,
                fontsize=self.config.font_size,
                fontfamily=self.config.font_family,
                color=self.config.color_palette["text"],
                ha="left",
                va="top",
                wrap=True,
            )

            buf = io.BytesIO()
            fig.savefig(buf, format="png", facecolor=self.config.color_palette["background"], dpi=100)
            plt.close(fig)
            buf.seek(0)
            png_bytes = buf.read()
        except ImportError:
            png_bytes = self._build_fallback_png(title, lines)

        b64 = base64.b64encode(png_bytes).decode("ascii")
        return HyperFrame(
            frame_id=f"frame_{sequence_index}_{hashlib.sha256(title.encode()).hexdigest()[:12]}",
            sequence_index=sequence_index,
            frame_data=b64,
            frame_metadata={"title": title, "line_count": len(lines)},
        )

    def _build_fallback_png(self, title: str, lines: List[str]) -> bytes:
        """Deterministic PNG generator using only Python stdlib (no matplotlib/Pillow).

        Renders at reduced resolution for performance; this is a fallback only.
        """
        import struct
        import zlib

        # Use reduced canvas for stdlib-only fallback performance
        w, h = 640, 360
        bg = (13, 17, 23)
        header = (45, 50, 60)
        text_rows = [title] + lines
        bar_height = 16
        gap = 3
        start_y = 24

        # Build scanlines as flat bytearray for speed
        raw = bytearray()
        for y in range(h):
            row = bytearray()
            if y < 24:
                color = header
            else:
                color = bg
                for i, _line in enumerate(text_rows[:25]):
                    y0 = start_y + i * (bar_height + gap)
                    if y0 <= y < min(y0 + bar_height, h):
                        color = (45 + (i * 7) % 180, 60 + (i * 11) % 150, 80 + (i * 13) % 120)
                        break
            row.append(0)  # filter byte
            r, g, b = color
            row.extend(bytes([r, g, b]) * w)
            raw.extend(row)

        compressed = zlib.compress(bytes(raw))

        sig = b"\x89PNG\r\n\x1a\n"

        def chunk(type_name: bytes, data: bytes) -> bytes:
            cs = struct.pack(">I", len(data)) + type_name + data
            crc = zlib.crc32(cs[4:]) & 0xFFFFFFFF
            return cs + struct.pack(">I", crc)

        ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
        return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", compressed) + chunk(b"IEND", b"")

    # ------------------------------------------------------------------
    # Formatters
    # ------------------------------------------------------------------

    def _format_baseline(self, report: SemanticDriftReport) -> List[str]:
        return [
            f"Baseline Snapshot: {report.baseline_snapshot_id}",
            f"Modified Snapshot: {report.modified_snapshot_id}",
            f"Total Deltas Detected: {len(report.deltas)}",
            f"Input Hash: {report.input_hash[:24]}...",
            f"Report Hash: {report.report_hash[:24]}...",
        ]

    def _format_delta_group(self, delta_type: str, group: List[SemanticDelta]) -> List[str]:
        lines = [f"Type: {delta_type} | Count: {len(group)}", "-" * 40]
        for d in group[:20]:  # bounded display
            lines.append(f"  [{d.severity}] {d.path}: {d.description}")
        if len(group) > 20:
            lines.append(f"  ... and {len(group) - 20} more")
        return lines

    def _format_aggregate(self, report: SemanticDriftReport) -> List[str]:
        lines = [
            "AGGREGATE DRIFT SCORES",
            "-" * 40,
            f"Total Drift Score: {report.total_drift_score:.4f}",
            f"Structural Drift:  {report.structural_drift:.4f}",
            f"Semantic Drift:    {report.semantic_drift:.4f}",
            f"High Severity Deltas: {len(report.high_severity_deltas)}",
            "",
            "Delta Counts by Type:",
        ]
        for dt in sorted(report.delta_counts.keys()):
            lines.append(f"  {dt}: {report.delta_counts[dt]}")
        return lines

    def _format_topology_overview(self, graph: RiskPropagationGraph) -> List[str]:
        return [
            f"Topology Graph: {graph.topology_graph_id}",
            f"Total Nodes: {len(graph.nodes)}",
            f"Total Edges: {len(graph.edges)}",
            "",
            "All nodes in NONE risk state (baseline view)",
        ]

    def _format_direct_blast(self, graph: RiskPropagationGraph) -> List[str]:
        direct = [n for n in graph.nodes.values() if n.in_direct_blast_radius]
        lines = [
            f"Direct Blast Radius Nodes: {len(direct)}",
            "-" * 40,
        ]
        for n in direct[:30]:
            lines.append(f"  {n.node_id} [{n.node_type}] -> {n.risk_level}")
        return lines

    def _format_propagation_depth(self, graph: RiskPropagationGraph) -> List[str]:
        by_depth: Dict[int, List[str]] = {}
        for n in graph.nodes.values():
            if n.propagation_depth > 0:
                by_depth.setdefault(n.propagation_depth, []).append(n.node_id)
        lines = ["Propagation Depth Analysis", "-" * 40]
        for d in sorted(by_depth.keys()):
            lines.append(f"  Depth {d}: {len(by_depth[d])} nodes")
        lines.append(f"Max Propagation Depth: {graph.max_propagation_depth}")
        return lines

    def _format_full_risk(self, graph: RiskPropagationGraph) -> List[str]:
        by_level: Dict[str, List[str]] = {}
        for n in graph.nodes.values():
            by_level.setdefault(n.risk_level, []).append(n.node_id)
        lines = ["Full Risk Distribution", "-" * 40]
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "NONE"):
            count = len(by_level.get(level, []))
            lines.append(f"  {level}: {count} nodes")
        return lines

    def _format_risk_aggregate(self, graph: RiskPropagationGraph) -> List[str]:
        return [
            "RISK PROPAGATION AGGREGATE",
            "-" * 40,
            f"Total Nodes at Risk: {graph.total_nodes_at_risk}",
            f"Propagating Edges:   {graph.total_edges_propagating}",
            f"Max Propagation Depth: {graph.max_propagation_depth}",
            f"Critical Nodes:      {len(graph.critical_nodes)}",
            f"High Nodes:          {len(graph.high_nodes)}",
            f"Graph Hash:          {graph.graph_hash[:24]}...",
        ]
