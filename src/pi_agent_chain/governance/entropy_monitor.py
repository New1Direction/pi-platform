"""Entropy Monitor.

Tracks ambiguity reduction across state transitions.
Every transition must reduce entropy. If entropy increases, the transition is suspicious.

Entropy is measured as:
- count of unknown/inferred fields
- structural complexity (branching)
- semantic ambiguity (low-confidence classifications)

The system only moves toward compression and constraint.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from pi_agent_chain.models import (
    DependencyGraph,
    ExtractedProtocolSkeleton,
    SemanticIRTrace,
    SynthesizedSpec,
)


class EntropySnapshot(BaseModel):
    """Immutable entropy reading at a point in time."""

    state: str
    unknown_field_count: int = 0
    branch_count: int = 0
    low_confidence_count: int = 0
    structural_complexity: int = 0
    entropy_score: float = 0.0
    timestamp: str = Field(
        default_factory=lambda: __import__("datetime").datetime.utcnow().isoformat()
    )


class EntropyMonitor:
    """Ambiguity reduction tracker.

    Maintains an append-only log of entropy snapshots.
    If a new snapshot has higher entropy than the previous, raises flag.
    """

    def __init__(self) -> None:
        self._snapshots: List[EntropySnapshot] = []

    def capture(self, state: str, artifact: Any) -> EntropySnapshot:
        """Compute entropy for a given state + artifact."""
        snapshot = self._compute(state, artifact)
        self._snapshots.append(snapshot)
        return snapshot

    def check_monotonic_decrease(self) -> Optional[str]:
        """Verify entropy has not increased across the last transition.

        Returns None if entropy decreased or stayed flat.
        Returns warning string if entropy increased (entropy leakage).
        """
        if len(self._snapshots) < 2:
            return None
        prev = self._snapshots[-2]
        curr = self._snapshots[-1]
        if curr.entropy_score > prev.entropy_score + 1e-6:
            return (
                f"ENTROPY_INCREASE: {prev.state}({prev.entropy_score:.4f}) -> "
                f"{curr.state}({curr.entropy_score:.4f})"
            )
        return None

    def _compute(self, state: str, artifact: Any) -> EntropySnapshot:
        unknown = 0
        low_conf = 0
        branches = 0
        complexity = 0

        if isinstance(artifact, SemanticIRTrace):
            unknown = sum(1 for f in artifact.fields if "UNKNOWN" in f.inferred_type)
            low_conf = sum(1 for f in artifact.fields if f.confidence < 0.87)
            branches = len(artifact.fields)
            complexity = len(artifact.fields)

        elif isinstance(artifact, DependencyGraph):
            branches = len(artifact.edges)
            complexity = len(artifact.edges) + len(artifact.nodes)

        elif isinstance(artifact, SynthesizedSpec):
            # Synthesis should reduce entropy (fewer unknowns)
            try:
                import json
                spec = json.loads(artifact.spec_json)
                paths = spec.get("paths", {})
                branches = sum(len(methods) for methods in paths.values())
                complexity = len(paths)
            except Exception:
                branches = 0
                complexity = 0

        elif isinstance(artifact, ExtractedProtocolSkeleton):
            # Structural extraction is deterministic — low entropy
            branches = (
                len(artifact.request_uri_segments)
                + len(artifact.request_query_keys)
                + len(artifact.request_header_keys)
            )
            complexity = branches

        # Composite: more unknowns + low-confidence = higher entropy
        score = (unknown * 2.0 + low_conf * 1.5 + branches * 0.1 + complexity * 0.05)

        return EntropySnapshot(
            state=state,
            unknown_field_count=unknown,
            low_confidence_count=low_conf,
            branch_count=branches,
            structural_complexity=complexity,
            entropy_score=score,
        )

    @property
    def history(self) -> List[EntropySnapshot]:
        return list(self._snapshots)
