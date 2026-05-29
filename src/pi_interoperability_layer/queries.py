"""Semantic Query API for topology, replay, and auth traversal.

Deterministic read-only queries against semantic snapshots.
No inference. No LLM calls. No mutation of stored state.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pi_interoperability_layer.registry import SnapshotRecord, SnapshotRegistry


class SemanticQueryResult:
    """Deterministic query result with provenance."""

    def __init__(self, query_id: str, snapshot_id: str, results: List[Dict[str, Any]]) -> None:
        self.query_id = query_id
        self.snapshot_id = snapshot_id
        self.results = results

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_id": self.query_id,
            "snapshot_id": self.snapshot_id,
            "result_count": len(self.results),
            "results": self.results,
        }


class SemanticQueryEngine:
    """Deterministic query engine for semantic snapshots."""

    def __init__(self, registry: SnapshotRegistry) -> None:
        self.registry = registry

    def query_endpoints_by_mutation_class(
        self,
        snapshot_id: str,
        mutation_class: str,
    ) -> SemanticQueryResult:
        """Return all endpoints with a given mutation class."""
        snap = self._load(snapshot_id)
        traces = snap.payload.get("traces", [])
        matches = [
            {"endpoint": t.get("endpoint_template"), "method": t.get("method")}
            for t in traces
            if t.get("mutation_class") == mutation_class
        ]
        return SemanticQueryResult(
            query_id=f"q_mutation_{mutation_class}",
            snapshot_id=snapshot_id,
            results=matches,
        )

    def query_replay_surface(
        self,
        snapshot_id: str,
        replay_class: Optional[str] = None,
    ) -> SemanticQueryResult:
        """Return replay surface endpoints."""
        snap = self._load(snapshot_id)
        traces = snap.payload.get("traces", [])
        if replay_class:
            matches = [
                {"endpoint": t.get("endpoint_template"), "method": t.get("method"), "replay_class": t.get("replay_class")}
                for t in traces
                if t.get("replay_class") == replay_class
            ]
        else:
            matches = [
                {"endpoint": t.get("endpoint_template"), "method": t.get("method"), "replay_class": t.get("replay_class")}
                for t in traces
            ]
        return SemanticQueryResult(
            query_id="q_replay_surface",
            snapshot_id=snapshot_id,
            results=matches,
        )

    def query_auth_boundaries(
        self,
        snapshot_id: str,
    ) -> SemanticQueryResult:
        """Return auth invariants and their affected endpoints."""
        snap = self._load(snapshot_id)
        auth = snap.payload.get("auth", [])
        matches = [
            {
                "invariant_id": a.get("invariant_id"),
                "invariant_type": a.get("invariant_type"),
                "affected_endpoints": a.get("affected_endpoints", []),
            }
            for a in auth
        ]
        return SemanticQueryResult(
            query_id="q_auth_boundaries",
            snapshot_id=snapshot_id,
            results=matches,
        )

    def query_topology_lineage(
        self,
        snapshot_id: str,
        endpoint: str,
    ) -> SemanticQueryResult:
        """Return upstream/downstream lineage for an endpoint."""
        snap = self._load(snapshot_id)
        edges = snap.payload.get("graph", {}).get("edges", [])
        upstream = [e["upstream_endpoint"] for e in edges if e.get("downstream_endpoint") == endpoint]
        downstream = [e["downstream_endpoint"] for e in edges if e.get("upstream_endpoint") == endpoint]
        return SemanticQueryResult(
            query_id=f"q_lineage_{endpoint}",
            snapshot_id=snapshot_id,
            results=[{"endpoint": endpoint, "upstream": upstream, "downstream": downstream}],
        )

    def query_drift_summary(
        self,
        bundle_id: str,
    ) -> SemanticQueryResult:
        """Return drift summary from a replay bundle."""
        bundle = self.registry.load_bundle(bundle_id)
        if bundle is None:
            return SemanticQueryResult(
                query_id="q_drift_summary",
                snapshot_id=bundle_id,
                results=[],
            )
        # Load diff report from modified snapshot payload if available
        mod_snap = self.registry.load_snapshot(bundle.modified_snapshot_id)
        diff = mod_snap.payload.get("diff_report", {}) if mod_snap else {}
        results = [
            {
                "drift_score": diff.get("drift_score"),
                "structural_delta_score": diff.get("structural_delta_score"),
                "semantic_delta_score": diff.get("semantic_delta_score"),
                "state_mutation_expansion": diff.get("state_mutation_expansion"),
                "replay_surface_expansion": diff.get("replay_surface_expansion"),
            }
        ]
        return SemanticQueryResult(
            query_id="q_drift_summary",
            snapshot_id=bundle.modified_snapshot_id,
            results=results,
        )

    def _load(self, snapshot_id: str) -> SnapshotRecord:
        record = self.registry.load_snapshot(snapshot_id)
        if record is None:
            raise ValueError(f"Snapshot not found: {snapshot_id}")
        return record

    # ── Telemetry Governance Queries ──────────────────────────────────

    def query_secret_exposure(self, snapshot_id: str) -> SemanticQueryResult:
        """Return detected secret/token exposures from TelemetryExposureReport."""
        snap = self._load(snapshot_id)
        findings = snap.payload.get("findings", [])
        secret_findings = [f for f in findings if f.get("rule") == "token_leakage"]
        return SemanticQueryResult(
            query_id="q_secret_exposure",
            snapshot_id=snapshot_id,
            results=secret_findings,
        )

    def query_sensitive_paths(self, snapshot_id: str) -> SemanticQueryResult:
        """Return endpoints handling sensitive fields from SensitiveFlowReport."""
        snap = self._load(snapshot_id)
        propagation = snap.payload.get("field_propagation", [])
        return SemanticQueryResult(
            query_id="q_sensitive_paths",
            snapshot_id=snapshot_id,
            results=propagation,
        )

    def query_replay_sanitization(self, bundle_id: str) -> SemanticQueryResult:
        """Return replay sanitization coverage from SanitizedReplayBundle."""
        bundle = self.registry.load_bundle(bundle_id)
        if bundle is None:
            return SemanticQueryResult(query_id="q_replay_sanitization", snapshot_id=bundle_id, results=[])
        # Load bundle snapshot if stored as snapshot
        snap = self.registry.load_snapshot(bundle_id)
        if snap is None:
            return SemanticQueryResult(query_id="q_replay_sanitization", snapshot_id=bundle_id, results=[])
        sanitized = snap.payload.get("sanitized_slots", [])
        redactions = snap.payload.get("redaction_log", [])
        return SemanticQueryResult(
            query_id="q_replay_sanitization",
            snapshot_id=bundle_id,
            results=[{
                "sanitized_slot_count": len(sanitized),
                "redaction_count": len(redactions),
                "replay_equivalence_preserved": snap.payload.get("replay_equivalence_preserved", False),
            }],
        )

    def query_observability_drift(self, snapshot_id: str) -> SemanticQueryResult:
        """Return observability drift findings."""
        snap = self._load(snapshot_id)
        snap.payload.get("findings", [])
        drift = [
            {
                "verbosity_expansion": snap.payload.get("verbosity_expansion"),
                "new_sensitive_fields": snap.payload.get("new_sensitive_fields", []),
                "new_metadata_keys": snap.payload.get("new_metadata_keys", []),
                "drift_score": snap.payload.get("drift_score", 0),
            }
        ]
        return SemanticQueryResult(
            query_id="q_observability_drift",
            snapshot_id=snapshot_id,
            results=drift,
        )

    def query_compliance_violations(self, snapshot_id: str) -> SemanticQueryResult:
        """Return compliance violations from ComplianceReport."""
        snap = self._load(snapshot_id)
        violations = snap.payload.get("violations", [])
        return SemanticQueryResult(
            query_id="q_compliance_violations",
            snapshot_id=snapshot_id,
            results=violations,
        )
