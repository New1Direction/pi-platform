"""Delta computation functions for the Deterministic Behavioral Delta Runtime.

Pure functions: snapshot_in, snapshot_out -> delta records.
No side effects. No LLM calls. Bounded traversal.
"""

from __future__ import annotations

from typing import Dict, List

from pi_semantic_diff.models import (
    AuthDelta,
    AuthInvariant,
    DependencyDelta,
    DependencyGraph,
    EndpointDelta,
    FieldDelta,
    ReplaySurfaceDelta,
    SemanticField,
    SemanticIRTrace,
    StateEdge,
)

# ──────────────────────────────
#  Endpoint Deltas
# ──────────────────────────────

def _trace_key(t: SemanticIRTrace) -> str:
    return f"{t.method}:{t.endpoint_template}"


def _field_key(f: SemanticField) -> str:
    return f.path


def compute_endpoint_deltas(
    baseline: List[SemanticIRTrace],
    modified: List[SemanticIRTrace],
    max_deltas: int = 512,
) -> List[EndpointDelta]:
    """Compute deterministic endpoint-level deltas between two trace sets."""
    base_map: Dict[str, SemanticIRTrace] = {_trace_key(t): t for t in baseline}
    mod_map: Dict[str, SemanticIRTrace] = {_trace_key(t): t for t in modified}

    deltas: List[EndpointDelta] = []

    # Removed endpoints
    for key, trace in base_map.items():
        if key not in mod_map:
            deltas.append(
                EndpointDelta(
                    endpoint_template=trace.endpoint_template,
                    method=trace.method,
                    presence="REMOVED",
                    baseline_mutation_class=getattr(trace, "mutation_class", "UNKNOWN"),
                    modified_mutation_class="UNKNOWN",
                    provenance=["baseline_snapshot"],
                )
            )
            if len(deltas) >= max_deltas:
                return deltas

    # Added / changed endpoints
    for key, mod_trace in mod_map.items():
        if key not in base_map:
            deltas.append(
                EndpointDelta(
                    endpoint_template=mod_trace.endpoint_template,
                    method=mod_trace.method,
                    presence="ADDED",
                    baseline_mutation_class="UNKNOWN",
                    modified_mutation_class=getattr(mod_trace, "mutation_class", "UNKNOWN"),
                    provenance=["modified_snapshot"],
                )
            )
            if len(deltas) >= max_deltas:
                return deltas
            continue

        base_trace = base_map[key]
        field_deltas = _compute_field_deltas(base_trace.fields, mod_trace.fields, max_deltas - len(deltas))
        mutation_transition = _mutation_transition(base_trace, mod_trace)
        replay_transition = _replay_transition(base_trace, mod_trace)

        if field_deltas or mutation_transition or replay_transition:
            deltas.append(
                EndpointDelta(
                    endpoint_template=mod_trace.endpoint_template,
                    method=mod_trace.method,
                    presence="UNCHANGED",
                    field_deltas=field_deltas,
                    baseline_mutation_class=getattr(base_trace, "mutation_class", "UNKNOWN"),
                    modified_mutation_class=getattr(mod_trace, "mutation_class", "UNKNOWN"),
                    mutation_class_transition=mutation_transition,
                    baseline_replay_class=getattr(base_trace, "replay_class", "UNKNOWN"),
                    modified_replay_class=getattr(mod_trace, "replay_class", "UNKNOWN"),
                    replay_class_transition=replay_transition,
                    provenance=["baseline_snapshot", "modified_snapshot"],
                )
            )
            if len(deltas) >= max_deltas:
                return deltas

    return deltas


def _compute_field_deltas(
    base_fields: List[SemanticField],
    mod_fields: List[SemanticField],
    max_count: int,
) -> List[FieldDelta]:
    base_map = {_field_key(f): f for f in base_fields}
    mod_map = {_field_key(f): f for f in mod_fields}
    deltas: List[FieldDelta] = []

    for key, bf in base_map.items():
        if key not in mod_map:
            deltas.append(FieldDelta(field_path=key, delta_type="REMOVED", severity="WARNING"))
            if len(deltas) >= max_count:
                return deltas
        else:
            mf = mod_map[key]
            if bf.inferred_type != mf.inferred_type:
                deltas.append(
                    FieldDelta(
                        field_path=key,
                        delta_type="TYPE_CHANGED",
                        baseline_value=bf.inferred_type,
                        modified_value=mf.inferred_type,
                        severity="CRITICAL",
                    )
                )
                if len(deltas) >= max_count:
                    return deltas
            if abs(bf.confidence - mf.confidence) > 0.1:
                deltas.append(
                    FieldDelta(
                        field_path=key,
                        delta_type="CONFIDENCE_CHANGED",
                        baseline_value=bf.confidence,
                        modified_value=mf.confidence,
                        severity="INFO",
                    )
                )
                if len(deltas) >= max_count:
                    return deltas

    for key, mf in mod_map.items():
        if key not in base_map:
            deltas.append(FieldDelta(field_path=key, delta_type="ADDED", severity="INFO"))
            if len(deltas) >= max_count:
                return deltas

    return deltas


def _mutation_transition(base: SemanticIRTrace, mod: SemanticIRTrace) -> bool:
    b = getattr(base, "mutation_class", "UNKNOWN")
    m = getattr(mod, "mutation_class", "UNKNOWN")
    # Escalation: any move away from IDEMPOTENT_READ is a transition
    if b != m and (b == "IDEMPOTENT_READ" or m in ("STATEFUL_MUTATION", "DESTRUCTIVE_MUTATION")):
        return True
    return b != m


def _replay_transition(base: SemanticIRTrace, mod: SemanticIRTrace) -> bool:
    b = getattr(base, "replay_class", "UNKNOWN")
    m = getattr(mod, "replay_class", "UNKNOWN")
    # Degradation: any move away from replayable is a transition
    if b != m and (b in ("PURE_REPLAYABLE", "IDEMPOTENT") and m in ("NON_REPLAYABLE", "SIDE_EFFECT_RISK")):
        return True
    return b != m


# ──────────────────────────────
#  Dependency Graph Deltas
# ──────────────────────────────

def _edge_key(e: StateEdge) -> str:
    return f"{e.upstream_endpoint}:{e.upstream_field}->{e.downstream_endpoint}:{e.downstream_field}"


def compute_dependency_deltas(
    baseline: DependencyGraph,
    modified: DependencyGraph,
    max_deltas: int = 512,
) -> List[DependencyDelta]:
    """Compute deterministic dependency graph evolution deltas."""
    base_edges = {_edge_key(e): e for e in baseline.edges}
    mod_edges = {_edge_key(e): e for e in modified.edges}
    base_nodes = set(baseline.nodes)
    mod_nodes = set(modified.nodes)

    deltas: List[DependencyDelta] = []

    # Removed edges
    for key, edge in base_edges.items():
        if key not in mod_edges:
            deltas.append(
                DependencyDelta(
                    delta_type="EDGE_REMOVED",
                    edge=edge,
                    upstream_endpoint=edge.upstream_endpoint,
                    downstream_endpoint=edge.downstream_endpoint,
                )
            )
            if len(deltas) >= max_deltas:
                return deltas

    # Added edges
    for key, edge in mod_edges.items():
        if key not in base_edges:
            deltas.append(
                DependencyDelta(
                    delta_type="EDGE_ADDED",
                    edge=edge,
                    upstream_endpoint=edge.upstream_endpoint,
                    downstream_endpoint=edge.downstream_endpoint,
                )
            )
            if len(deltas) >= max_deltas:
                return deltas

    # Removed nodes
    for node in base_nodes - mod_nodes:
        deltas.append(DependencyDelta(delta_type="NODE_REMOVED", node=node))
        if len(deltas) >= max_deltas:
            return deltas

    # Added nodes
    for node in mod_nodes - base_nodes:
        deltas.append(DependencyDelta(delta_type="NODE_ADDED", node=node))
        if len(deltas) >= max_deltas:
            return deltas

    return deltas


# ──────────────────────────────
#  Auth Deltas
# ──────────────────────────────

def compute_auth_deltas(
    baseline: List[AuthInvariant],
    modified: List[AuthInvariant],
    max_deltas: int = 256,
) -> List[AuthDelta]:
    """Compute deterministic auth invariant evolution deltas."""
    base_map = {inv.invariant_id: inv for inv in baseline}
    mod_map = {inv.invariant_id: inv for inv in modified}

    deltas: List[AuthDelta] = []

    for inv_id, b_inv in base_map.items():
        if inv_id not in mod_map:
            deltas.append(
                AuthDelta(
                    invariant_id=inv_id,
                    delta_type="REMOVED",
                    affected_endpoints_delta=-len(b_inv.affected_endpoints),
                )
            )
        else:
            m_inv = mod_map[inv_id]
            if b_inv.rotation_class != m_inv.rotation_class:
                deltas.append(
                    AuthDelta(
                        invariant_id=inv_id,
                        delta_type="ROTATION_CLASS_CHANGED",
                        affected_endpoints_delta=len(m_inv.affected_endpoints) - len(b_inv.affected_endpoints),
                    )
                )
            elif len(b_inv.affected_endpoints) != len(m_inv.affected_endpoints):
                deltas.append(
                    AuthDelta(
                        invariant_id=inv_id,
                        delta_type="BINDING_CHANGED",
                        affected_endpoints_delta=len(m_inv.affected_endpoints) - len(b_inv.affected_endpoints),
                    )
                )
        if len(deltas) >= max_deltas:
            return deltas

    for inv_id, m_inv in mod_map.items():
        if inv_id not in base_map:
            deltas.append(
                AuthDelta(
                    invariant_id=inv_id,
                    delta_type="ADDED",
                    affected_endpoints_delta=len(m_inv.affected_endpoints),
                )
            )
            if len(deltas) >= max_deltas:
                return deltas

    return deltas


# ──────────────────────────────
#  Replay Surface Deltas
# ──────────────────────────────

def compute_replay_surface_deltas(
    baseline: List[SemanticIRTrace],
    modified: List[SemanticIRTrace],
    max_deltas: int = 512,
) -> List[ReplaySurfaceDelta]:
    """Compute deterministic replay surface change deltas."""
    base_map = {_trace_key(t): t for t in baseline}
    mod_map = {_trace_key(t): t for t in modified}
    deltas: List[ReplaySurfaceDelta] = []

    for key, m_trace in mod_map.items():
        b_trace = base_map.get(key)
        if b_trace is None:
            # New endpoint: check if replayable
            m_replay = getattr(m_trace, "replay_class", "UNKNOWN")
            if m_replay in ("NON_REPLAYABLE", "SIDE_EFFECT_RISK"):
                deltas.append(
                    ReplaySurfaceDelta(
                        endpoint_template=m_trace.endpoint_template,
                        method=m_trace.method,
                        replayable_delta=True,
                    )
                )
            continue

        b_replay = getattr(b_trace, "replay_class", "UNKNOWN")
        m_replay = getattr(m_trace, "replay_class", "UNKNOWN")
        b_sandbox = getattr(b_trace, "sandbox_required", False)
        m_sandbox = getattr(m_trace, "sandbox_required", False)
        b_prod = getattr(b_trace, "production_replay_prohibited", False)
        m_prod = getattr(m_trace, "production_replay_prohibited", False)

        if b_replay != m_replay or b_sandbox != m_sandbox or b_prod != m_prod:
            deltas.append(
                ReplaySurfaceDelta(
                    endpoint_template=m_trace.endpoint_template,
                    method=m_trace.method,
                    replayable_delta=(b_replay != m_replay),
                    sandbox_required_delta=(b_sandbox != m_sandbox),
                    production_replay_prohibited_delta=(b_prod != m_prod),
                )
            )
            if len(deltas) >= max_deltas:
                return deltas

    return deltas


# ──────────────────────────────
#  Scoring Functions
# ──────────────────────────────

def compute_structural_delta_score(
    endpoint_deltas: List[EndpointDelta],
    dependency_deltas: List[DependencyDelta],
) -> float:
    """Bounded deterministic structural delta score [0,1]."""
    score = 0.0
    for d in endpoint_deltas:
        if d.presence in ("ADDED", "REMOVED"):
            score += 0.1
        score += len(d.field_deltas) * 0.02
    for d in dependency_deltas:
        if d.delta_type in ("EDGE_ADDED", "EDGE_REMOVED"):
            score += 0.05
        if d.delta_type in ("NODE_ADDED", "NODE_REMOVED"):
            score += 0.03
    return min(score, 1.0)


def compute_semantic_delta_score(endpoint_deltas: List[EndpointDelta]) -> float:
    """Bounded deterministic semantic delta score [0,1]."""
    score = 0.0
    for d in endpoint_deltas:
        for fd in d.field_deltas:
            if fd.delta_type == "TYPE_CHANGED":
                score += 0.15
            elif fd.delta_type == "REMOVED":
                score += 0.05
            else:
                score += 0.01
    return min(score, 1.0)


def compute_drift_score(structural: float, semantic: float, mutation_exp: int, replay_exp: int) -> float:
    """Bounded deterministic drift score [0,1]."""
    score = structural * 0.3 + semantic * 0.4 + min(mutation_exp * 0.05, 0.2) + min(replay_exp * 0.05, 0.1)
    return min(score, 1.0)
