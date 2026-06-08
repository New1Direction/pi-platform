"""Reproducibility regression tests for the pi_agent_chain determinism claim.

The PI Platform brands itself a "deterministic kernel" and sells its SHA-256
hashes as reproducibility proof. These tests pin that claim: every
content-addressed / identity hash in this subsystem MUST be a pure function of
the LOGICAL content plus structural/causal position, and MUST NOT vary with
wall-clock time (``datetime.utcnow``/``time.time``) or random ids
(``uuid4``)-derived values.

Each test builds the SAME logical object TWICE as two fresh instances, forces a
wall-clock gap between them, and asserts the hash is byte-identical. It also
asserts the volatile metadata field (timestamp / random id) is STILL recorded
on the object — we exclude it from the hash, we do not delete it.

Mirrors the reference fix already proven on pi_event_fabric/bus/core.py.
"""

import hashlib
import json
import time
from datetime import datetime

from pi_agent_chain.artifact_registry import ArtifactRegistry
from pi_agent_chain.ledger import StateLedger
from pi_agent_chain.models import (
    DependencyGraph,
    ExecutionTrace,
    SemanticField,
    SemanticIRTrace,
    VerificationReport,
)


def _make_trace() -> SemanticIRTrace:
    """Build a logically identical SemanticIRTrace (frozen_at = wall-clock now)."""
    return SemanticIRTrace(
        endpoint_template="/users/{id}",
        method="GET",
        fields=[
            SemanticField(
                path="response.body.id",
                inferred_type="UUIDv4",
                confidence=0.98,
                entropy_score=0.1,
            ),
        ],
        is_frozen=True,
        frozen_at=datetime.utcnow(),
    )


class TestHashReproducibility:
    """Same logical input -> same hash, across two fresh instances at
    different wall-clock times."""

    def test_semantic_ir_trace_hash_is_reproducible(self):
        a = _make_trace()
        time.sleep(0.01)  # force a distinct wall-clock for frozen_at
        b = _make_trace()

        # The wall-clock metadata genuinely differs between the two builds...
        assert a.frozen_at is not None
        assert b.frozen_at is not None
        assert a.frozen_at != b.frozen_at
        # ...yet the content-addressed hash is identical.
        assert a.compute_hash() == b.compute_hash()

    def test_verification_report_hash_is_reproducible(self):
        a = VerificationReport(passed=True, tested_endpoints=2, total_endpoints=2)
        time.sleep(0.01)
        b = VerificationReport(passed=True, tested_endpoints=2, total_endpoints=2)

        # verified_at is still recorded as metadata on both instances.
        assert a.verified_at is not None
        assert b.verified_at is not None
        # Hash excludes verified_at -> reproducible.
        assert a.compute_hash() == b.compute_hash()

    def test_dependency_graph_hash_ignores_random_session_id(self):
        # session_window_id is uuid4-derived (random). Two graphs with the same
        # logical content but different random session ids must hash the same.
        a = DependencyGraph(edges=[], nodes=["GET /a", "GET /b"], session_window_id="sess-aaaa")
        b = DependencyGraph(edges=[], nodes=["GET /a", "GET /b"], session_window_id="sess-bbbb")

        # The random id is still recorded on the model as metadata.
        assert a.session_window_id == "sess-aaaa"
        assert b.session_window_id == "sess-bbbb"
        # Hash excludes the random id -> identical.
        assert a.compute_hash() == b.compute_hash()

    def test_ledger_state_hash_is_reproducible(self):
        def build_ledger() -> StateLedger:
            ledger = StateLedger(":memory:")
            ledger.append(
                ExecutionTrace(
                    trace_id="trace-fixed",
                    node_name="SemanticTyper",
                    input_payload_hash="abc123",
                    llm_seed=1337,
                    llm_temperature=0.0,
                    raw_output=json.dumps({"status": "SUCCESS"}),
                    is_valid_type=True,
                )
            )
            return ledger

        l1 = build_ledger()
        time.sleep(0.01)  # the per-row wall-clock timestamp differs between runs
        l2 = build_ledger()

        # The per-row timestamp is still recorded as metadata in the packet...
        packet1 = l1.get_state_packet("trace-fixed")
        assert "timestamp" in packet1["steps"][0]
        # ...but the headline state_hash is reproducible.
        assert l1.compute_state_hash("trace-fixed") == l2.compute_state_hash("trace-fixed")

    def test_ledger_state_hash_ignores_random_trace_id(self):
        # The trace_id is a random uuid4 correlation id; two ledgers holding the
        # same logical step content under different trace_ids must hash equal.
        def build_ledger(tid: str) -> StateLedger:
            ledger = StateLedger(":memory:")
            ledger.append(
                ExecutionTrace(
                    trace_id=tid,
                    node_name="PipelineDriver",
                    input_payload_hash="deadbeef",
                    llm_seed=1337,
                    llm_temperature=0.0,
                    raw_output=json.dumps({"status": "SUCCESS"}),
                    is_valid_type=True,
                )
            )
            return ledger

        l1 = build_ledger("11111111-1111-1111-1111-111111111111")
        l2 = build_ledger("22222222-2222-2222-2222-222222222222")

        h1 = l1.compute_state_hash("11111111-1111-1111-1111-111111111111")
        h2 = l2.compute_state_hash("22222222-2222-2222-2222-222222222222")
        assert h1 == h2

    def test_artifact_semantic_hash_is_reproducible(self):
        # derive_artifact content-addresses payload_json + semantic_hash +
        # artifact_id, excluding wall-clock (frozen_at) — captured_at still
        # records the wall-clock capture time separately.
        a = ArtifactRegistry.derive_artifact(_make_trace(), "SemanticIRTrace", "SemanticTyperNode")
        time.sleep(0.01)
        b = ArtifactRegistry.derive_artifact(_make_trace(), "SemanticIRTrace", "SemanticTyperNode")

        # Wall-clock capture time is still recorded as metadata.
        assert a.captured_at is not None
        assert b.captured_at is not None
        # Content-addressed identity is reproducible.
        assert a.semantic_hash == b.semantic_hash
        assert a.artifact_id == b.artifact_id

    def test_artifact_payload_hash_integrity_holds(self):
        # The provenance validator re-hashes payload_json and compares it to
        # semantic_hash. Content-addressing must keep these mutually consistent.
        art = ArtifactRegistry.derive_artifact(_make_trace(), "SemanticIRTrace", "SemanticTyperNode")
        recomputed = hashlib.sha256(art.payload_json.encode()).hexdigest()
        assert recomputed == art.semantic_hash
