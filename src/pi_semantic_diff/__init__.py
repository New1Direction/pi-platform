"""pi-semantic-diff: deterministic behavioral delta runtime for governed semantic pipelines."""

from pi_semantic_diff.models import (
    SemanticIRTrace,
    SemanticField,
    DependencyGraph,
    StateEdge,
    AuthInvariant,
    EndpointDelta,
    FieldDelta,
    DependencyDelta,
    AuthDelta,
    ReplaySurfaceDelta,
    SemanticDiffReport,
)
from pi_semantic_diff.runtime import DiffRuntime, DiffBounds
from pi_semantic_diff.deltas import (
    compute_endpoint_deltas,
    compute_dependency_deltas,
    compute_auth_deltas,
    compute_replay_surface_deltas,
    compute_structural_delta_score,
    compute_semantic_delta_score,
    compute_drift_score,
)

__version__ = "0.1.0"
