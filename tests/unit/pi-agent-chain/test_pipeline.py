"""Tests for the pi-semantic-recon pipeline."""

import pytest

from pi_agent_chain.ledger import StateLedger
from pi_agent_chain.models import (
    DependencyGraph,
    ExtractedProtocolSkeleton,
    NormalizedTrafficPacket,
    ReplayClass,
    SemanticIRTrace,
    SynthesizedSpec,
    VerificationReport,
)
from pi_agent_chain.nodes.acquisition_gateway import AcquisitionGatewayNode
from pi_agent_chain.nodes.flow_mapper import FlowMapperNode
from pi_agent_chain.nodes.ingress_parser import IngressParserNode
from pi_agent_chain.nodes.semantic_typer import SemanticTyperNode
from pi_agent_chain.nodes.spec_synthesizer import SpecSynthesizerNode
from pi_agent_chain.nodes.structural_extractor import StructuralExtractorNode
from pi_agent_chain.pipeline import PipelineDriver


# Real-looking JWT for deterministic classification
VALID_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3a9w4z0j3V"

RAW_REQUEST = f"""GET /api/v1/users/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer {VALID_JWT}\nAccept: application/json\n\n"""

RAW_RESPONSE = """HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\": \"550e8400-e29b-41d4-a716-446655440000\", \"created_at\": \"2024-05-18T12:34:56Z\", \"name\": \"Alice\", \"age\": 30}\n"""


def test_ingress_parser():
    node = IngressParserNode()
    packet = node.parse_raw(RAW_REQUEST, RAW_RESPONSE, url_override="https://api.example.com")
    assert isinstance(packet, NormalizedTrafficPacket)
    assert packet.method == "GET"
    assert packet.response_status == 200


def test_structural_extractor():
    parser = IngressParserNode()
    extractor = StructuralExtractorNode()
    packet = parser.parse_raw(RAW_REQUEST, RAW_RESPONSE, url_override="https://api.example.com")
    skel = extractor.extract(packet)
    assert isinstance(skel, ExtractedProtocolSkeleton)
    assert "id" in skel.response_payload_keys_flattened
    assert "created_at" in skel.response_payload_keys_flattened


def test_semantic_typer():
    parser = IngressParserNode()
    extractor = StructuralExtractorNode()
    typer = SemanticTyperNode(confidence_threshold=0.87)
    packet = parser.parse_raw(RAW_REQUEST, RAW_RESPONSE, url_override="https://api.example.com")
    skel = extractor.extract(packet)
    trace = typer.analyze(packet, skel)
    assert isinstance(trace, SemanticIRTrace)
    inferred = {f.path: f.inferred_type for f in trace.fields}
    assert any("UUIDv4" == v for v in inferred.values())
    assert trace.is_frozen


def test_flow_mapper():
    parser = IngressParserNode()
    extractor = StructuralExtractorNode()
    typer = SemanticTyperNode(confidence_threshold=0.87)
    packet = parser.parse_raw(RAW_REQUEST, RAW_RESPONSE, url_override="https://api.example.com")
    skel = extractor.extract(packet)
    trace = typer.analyze(packet, skel)
    mapper = FlowMapperNode()
    graph = mapper.map_flow([trace])
    assert isinstance(graph, DependencyGraph)


def test_spec_synthesizer():
    parser = IngressParserNode()
    extractor = StructuralExtractorNode()
    typer = SemanticTyperNode(confidence_threshold=0.87)
    mapper = FlowMapperNode()
    synthesizer = SpecSynthesizerNode()

    packet = parser.parse_raw(RAW_REQUEST, RAW_RESPONSE, url_override="https://api.example.com")
    skel = extractor.extract(packet)
    trace = typer.analyze(packet, skel)
    graph = mapper.map_flow([trace])
    spec = synthesizer.synthesize([trace], graph)

    assert isinstance(spec, SynthesizedSpec)
    assert spec.is_valid
    data = spec.openapi_dict()
    assert data["openapi"] == "3.1.0"


def test_ledger():
    ledger = StateLedger(":memory:")
    from pi_agent_chain.models import ExecutionTrace
    trace = ExecutionTrace(
        trace_id="test-123",
        node_name="IngressParser",
        input_payload_hash="abc123",
        llm_seed=1337,
        llm_temperature=0.0,
        raw_output="{}",
        is_valid_type=True,
    )
    ledger.append(trace)
    retrieved = ledger.get_trace("test-123")
    assert len(retrieved) == 1
    assert retrieved[0].node_name == "IngressParser"


def test_acquisition_gateway():
    gateway = AcquisitionGatewayNode(source="MANUAL")
    gov = gateway.from_raw_http_pair(RAW_REQUEST, RAW_RESPONSE, url_override="https://api.example.com")
    assert gov.truth.source == "MANUAL"
    assert gov.truth.canonical_hash
    assert gov.truth.packet_hash
    assert gov.packet.method == "GET"
    assert gov.packet.response_status == 200
    assert gov.truth.replay_class == ReplayClass.IDEMPOTENT


def test_replay_classification():
    gateway = AcquisitionGatewayNode()
    assert gateway._classify_replay_safety("GET", "/api/v1/users/list", []) == ReplayClass.PURE_REPLAYABLE
    assert gateway._classify_replay_safety("POST", "/api/v1/users/create", []) == ReplayClass.SIDE_EFFECT_RISK
    assert gateway._classify_replay_safety("DELETE", "/api/v1/users/123", []) == ReplayClass.NON_REPLAYABLE
    assert gateway._classify_replay_safety("GET", "/api/v1/users", []) == ReplayClass.IDEMPOTENT


def test_pipeline_driver():
    ledger = StateLedger(":memory:")
    driver = PipelineDriver(ledger=ledger, base_url="https://api.example.com")
    result = driver.run([(RAW_REQUEST, RAW_RESPONSE)])
    assert "trace_id" in result
    assert "governed_packets" in result
    assert result["status"] == "VERIFICATION_FAILURE"  # live API not reachable -> contradiction
    assert "state_hash" in result


def test_governance_kernel_transitions():
    from pi_agent_chain.governance import GovernanceKernel
    from pi_agent_chain.models import RuntimeState, WorkerStatus

    kernel = GovernanceKernel(
        root_goal_id="goal_test_001",
        objective_scope={"domain": "example.com", "mode": "passive"},
    )
    assert kernel.current_state == RuntimeState.REGISTERED
    assert not kernel.is_halted()

    # Valid transition: REGISTERED -> SCOPED via execute()
    resp = kernel.execute(
        worker_id="test_worker",
        target_state=RuntimeState.SCOPED,
        worker_fn=lambda env: {"payload": None, "type": "noop"},
    )
    assert resp.status == WorkerStatus.SUCCESS
    assert kernel.current_state == RuntimeState.SCOPED

    # Valid transition chain (depth-limited to 3)
    for state in [RuntimeState.CAPTURE_READY, RuntimeState.CAPTURING]:
        resp = kernel.execute(
            worker_id="test_worker",
            target_state=state,
            worker_fn=lambda env: {"payload": None, "type": "noop"},
        )
        assert resp.status == WorkerStatus.SUCCESS, f"Transition to {state} failed: {resp.errors}"

    # Valid transition: NORMALIZING should succeed
    resp = kernel.execute(
        worker_id="test_worker",
        target_state=RuntimeState.NORMALIZING,
        worker_fn=lambda env: {"payload": None, "type": "noop"},
    )
    assert resp.status == WorkerStatus.SUCCESS, f"Transition to NORMALIZING failed: {resp.errors}"

    # Invalid transition should produce violation (jump to COMPLETED)
    resp = kernel.execute(
        worker_id="test_worker",
        target_state=RuntimeState.COMPLETED,
        worker_fn=lambda env: {"payload": None, "type": "noop"},
    )
    assert resp.status == WorkerStatus.BRANCH_OVERFLOW
    assert kernel.is_halted()


def test_schema_gate_validation():
    from pi_agent_chain.governance.schema_gate import SchemaGate
    from pi_agent_chain.models import WorkerResponse

    gate = SchemaGate()
    response = WorkerResponse(root_goal_id="g1", worker_id="structural_extractor")

    # Valid payload (wrapper format)
    valid = {
        "payload": {"request_uri_segments": ["/v1", "/users"]},
        "type": "ExtractedProtocolSkeleton",
    }
    assert gate.validate("structural_extractor", valid, response) is None

    # Invalid payload (missing required field)
    invalid = {"timestamp": 1234567890, "method": "GET"}
    v = gate.validate("structural_extractor", invalid, response)
    assert v is not None
    assert v.rule == "INVALID_OUTPUT"


def test_objective_tracker_drift():
    from pi_agent_chain.governance.objective_tracker import ObjectiveTracker
    from pi_agent_chain.models import WorkerResponse

    tracker = ObjectiveTracker(
        root_goal_id="goal_original",
        objective_scope={"domain": "example.com"},
    )

    # Valid response
    ok = WorkerResponse(root_goal_id="goal_original", worker_id="w1")
    assert tracker.validate_worker_response(ok) is None

    # Drift detected
    bad = WorkerResponse(root_goal_id="goal_hijacked", worker_id="w1")
    v = tracker.validate_worker_response(bad)
    assert v is not None
    assert v.rule == "OBJECTIVE_DRIFT_DETECTED"
    assert v.severity == "CRITICAL"


def test_entropy_monitor_monotonicity():
    from pi_agent_chain.governance.entropy_monitor import EntropyMonitor
    from pi_agent_chain.models import SemanticIRTrace, SemanticField

    mon = EntropyMonitor()

    # First snapshot: high entropy (many unknowns)
    trace1 = SemanticIRTrace(
        endpoint_template="/test",
        method="GET",
        fields=[
            SemanticField(path="a", inferred_type="UNKNOWN_STR", confidence=0.5, entropy_score=0.9),
            SemanticField(path="b", inferred_type="UNKNOWN_HEX", confidence=0.4, entropy_score=0.9),
        ],
    )
    mon.capture("EXTRACTING", trace1)

    # Second snapshot: lower entropy (frozen, known types)
    trace2 = SemanticIRTrace(
        endpoint_template="/test",
        method="GET",
        fields=[
            SemanticField(path="a", inferred_type="STRING", confidence=0.95, entropy_score=0.3),
            SemanticField(path="b", inferred_type="UUIDv4", confidence=0.98, entropy_score=0.1),
        ],
    )
    mon.capture("ASSEMBLING_IR", trace2)

    # Should be clean (entropy decreased)
    assert mon.check_monotonic_decrease() is None

    # Third snapshot: higher entropy again (simulating corruption)
    trace3 = SemanticIRTrace(
        endpoint_template="/test",
        method="GET",
        fields=[
            SemanticField(path="a", inferred_type="UNKNOWN_STR", confidence=0.3, entropy_score=0.9),
            SemanticField(path="b", inferred_type="UNKNOWN_HEX", confidence=0.2, entropy_score=0.9),
            SemanticField(path="c", inferred_type="UNKNOWN_STR", confidence=0.1, entropy_score=0.9),
        ],
    )
    mon.capture("GENERATING_SPEC", trace3)

    # Should flag increase
    warning = mon.check_monotonic_decrease()
    assert warning is not None
    assert "ENTROPY_INCREASE" in warning


def test_provenance_validator_closure():
    import hashlib
    from pi_agent_chain.artifact_registry import ArtifactRegistry, SemanticArtifact
    from pi_agent_chain.models import EpistemicState
    from pi_agent_chain.verification.provenance_validator import ProvenanceValidator

    registry = ArtifactRegistry(":memory:")
    validator = ProvenanceValidator(registry)

    # Create OBSERVED parent with valid hash
    parent_payload = '{"type":"parent"}'
    parent_hash = hashlib.sha256(parent_payload.encode()).hexdigest()
    parent = SemanticArtifact(
        artifact_id="obs_001",
        artifact_type="NormalizedTrafficPacket",
        epistemic_state=EpistemicState.OBSERVED,
        semantic_hash=parent_hash,
        generated_by="AcquisitionGatewayNode",
        payload_json=parent_payload,
    )
    registry.store(parent)

    # Create INFERRED child with valid ancestry
    child_payload = '{"type":"child"}'
    child_hash = hashlib.sha256(child_payload.encode()).hexdigest()
    child = SemanticArtifact(
        artifact_id="inf_001",
        artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.INFERRED,
        semantic_hash=child_hash,
        generated_by="SemanticTyperNode",
        payload_json=child_payload,
        parent_artifact_ids=["obs_001"],
        evidence_refs=["artifact:obs_001"],
    )
    registry.store(child)

    allowed, violations = validator.can_promote(child, EpistemicState.VERIFIED)
    assert allowed, f"Expected closure but got: {[v.rule for v in violations]}"


def test_provenance_validator_orphaned():
    import hashlib
    from pi_agent_chain.artifact_registry import ArtifactRegistry, SemanticArtifact
    from pi_agent_chain.models import EpistemicState
    from pi_agent_chain.verification.provenance_validator import ProvenanceValidator

    registry = ArtifactRegistry(":memory:")
    validator = ProvenanceValidator(registry)

    # INFERRED artifact with no parents and no evidence = orphaned
    payload = '{"type":"orphan"}'
    h = hashlib.sha256(payload.encode()).hexdigest()
    orphan = SemanticArtifact(
        artifact_id="inf_orphan",
        artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.INFERRED,
        semantic_hash=h,
        generated_by="SemanticTyperNode",
        payload_json=payload,
    )
    registry.store(orphan)

    violations = validator.validate(orphan)
    rules = [v.rule for v in violations]
    assert "ORPHANED_ARTIFACT" in rules


def test_provenance_validator_cyclic():
    import hashlib
    from pi_agent_chain.artifact_registry import ArtifactRegistry, SemanticArtifact
    from pi_agent_chain.models import EpistemicState
    from pi_agent_chain.verification.provenance_validator import ProvenanceValidator

    registry = ArtifactRegistry(":memory:")
    validator = ProvenanceValidator(registry)

    # Create cyclic lineage: A -> B -> A (via latest A)
    payload_a = '{"type":"a"}'
    payload_b = '{"type":"b"}'
    hash_a = hashlib.sha256(payload_a.encode()).hexdigest()
    hash_b = hashlib.sha256(payload_b.encode()).hexdigest()

    art_a = SemanticArtifact(
        artifact_id="cyc_a",
        artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.OBSERVED,
        semantic_hash=hash_a,
        generated_by="AcquisitionGatewayNode",
        payload_json=payload_a,
    )
    registry.store(art_a)

    art_b = SemanticArtifact(
        artifact_id="cyc_b",
        artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.INFERRED,
        semantic_hash=hash_b,
        generated_by="SemanticTyperNode",
        payload_json=payload_b,
        parent_artifact_ids=["cyc_a"],
    )
    registry.store(art_b)

    # Now create a new version of A that points to B (cycle)
    art_a_cycle = SemanticArtifact(
        artifact_id="cyc_a",
        artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.OBSERVED,
        semantic_hash=hash_a,
        generated_by="AcquisitionGatewayNode",
        payload_json=payload_a,
        parent_artifact_ids=["cyc_b"],
    )
    registry.store(art_a_cycle)

    violations = validator.validate(art_a_cycle)
    rules = [v.rule for v in violations]
    assert "CYCLIC_PROVENANCE" in rules


def test_replay_validator_strict_equivalent():
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.verification.replay_validator import ReplayValidator

    validator = ReplayValidator()

    fields = [
        SemanticField(path="body.name", inferred_type="STRING", confidence=0.95, entropy_score=0.3),
        SemanticField(path="body.age", inferred_type="INTEGER", confidence=0.99, entropy_score=0.1),
    ]
    trace = SemanticIRTrace(
        endpoint_template="/users/{id}",
        method="GET",
        fields=fields,
        is_frozen=True,
        epistemic_state=EpistemicState.VERIFIED,
    )

    diff, violations = validator.compare(trace, trace)
    assert diff.replay_equivalence == "STRICT_EQUIVALENT"
    assert diff.structural_delta_score == 0.0
    assert diff.semantic_delta_score == 0.0
    assert len(violations) == 0


def test_replay_validator_semantic_equivalent_field_reorder():
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.verification.replay_validator import ReplayValidator

    validator = ReplayValidator()

    # Same fields, different list order (should be canonicalized to same)
    orig = SemanticIRTrace(
        endpoint_template="/users/{id}",
        method="GET",
        fields=[
            SemanticField(path="body.name", inferred_type="STRING", confidence=0.95, entropy_score=0.3),
            SemanticField(path="body.age", inferred_type="INTEGER", confidence=0.99, entropy_score=0.1),
        ],
        is_frozen=True,
    )
    replay = SemanticIRTrace(
        endpoint_template="/users/{id}",
        method="GET",
        fields=[
            SemanticField(path="body.age", inferred_type="INTEGER", confidence=0.99, entropy_score=0.1),
            SemanticField(path="body.name", inferred_type="STRING", confidence=0.95, entropy_score=0.3),
        ],
        is_frozen=True,
    )

    diff, violations = validator.compare(orig, replay)
    assert diff.replay_equivalence == "STRICT_EQUIVALENT"
    assert diff.structural_delta_score == 0.0
    assert len(violations) == 0


def test_replay_validator_partial_equivalent_added_field():
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.verification.replay_validator import ReplayValidator

    validator = ReplayValidator()

    orig = SemanticIRTrace(
        endpoint_template="/users/{id}",
        method="GET",
        fields=[
            SemanticField(path="body.name", inferred_type="STRING", confidence=0.95, entropy_score=0.3),
            SemanticField(path="body.age", inferred_type="INTEGER", confidence=0.99, entropy_score=0.1),
        ],
        is_frozen=True,
    )
    replay = SemanticIRTrace(
        endpoint_template="/users/{id}",
        method="GET",
        fields=[
            SemanticField(path="body.name", inferred_type="STRING", confidence=0.95, entropy_score=0.3),
            SemanticField(path="body.age", inferred_type="INTEGER", confidence=0.99, entropy_score=0.1),
            SemanticField(path="body.email", inferred_type="Email", confidence=0.92, entropy_score=0.4),
        ],
        is_frozen=True,
    )

    diff, violations = validator.compare(orig, replay)
    assert diff.replay_equivalence == "PARTIAL_EQUIVALENT"
    assert diff.structural_delta_score > 0.0
    assert "body.email" in diff.added_fields
    assert len(violations) == 0  # PARTIAL doesn't trigger violations at current thresholds


def test_replay_validator_non_equivalent_endpoint_changed():
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.verification.replay_validator import ReplayValidator

    validator = ReplayValidator()

    orig = SemanticIRTrace(
        endpoint_template="/users/{id}",
        method="GET",
        fields=[
            SemanticField(path="body.name", inferred_type="STRING", confidence=0.95, entropy_score=0.3),
        ],
        is_frozen=True,
    )
    replay = SemanticIRTrace(
        endpoint_template="/accounts/{id}",
        method="GET",
        fields=[
            SemanticField(path="body.name", inferred_type="STRING", confidence=0.95, entropy_score=0.3),
        ],
        is_frozen=True,
    )

    diff, violations = validator.compare(orig, replay)
    assert diff.replay_equivalence == "NON_EQUIVALENT"
    assert not diff.endpoint_stable
    assert len(violations) > 0
    assert any(v.rule == "REPLAY_NON_EQUIVALENT" for v in violations)


def test_replay_validator_auth_mutation_critical():
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.verification.replay_validator import ReplayValidator

    validator = ReplayValidator()

    orig = SemanticIRTrace(
        endpoint_template="/users/{id}",
        method="GET",
        fields=[
            SemanticField(path="header.authorization", inferred_type="JWT", confidence=0.95, entropy_score=0.8),
            SemanticField(path="body.name", inferred_type="STRING", confidence=0.95, entropy_score=0.3),
        ],
        is_frozen=True,
    )
    replay = SemanticIRTrace(
        endpoint_template="/users/{id}",
        method="GET",
        fields=[
            SemanticField(path="header.authorization", inferred_type="STRING", confidence=0.95, entropy_score=0.3),
            SemanticField(path="body.name", inferred_type="STRING", confidence=0.95, entropy_score=0.3),
        ],
        is_frozen=True,
    )

    diff, violations = validator.compare(orig, replay)
    # Auth material lost -> CRITICAL violation
    assert any(v.rule == "REPLAY_AUTH_MUTATION" and v.severity == "CRITICAL" for v in violations)
    assert "header.authorization" in [m.split(":")[0] for m in diff.auth_mutations]


def test_replay_validator_canonicalization_strips_timestamps():
    from datetime import datetime
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.verification.replay_validator import ReplayValidator

    validator = ReplayValidator()

    now = datetime.utcnow()
    orig = SemanticIRTrace(
        endpoint_template="/users/{id}",
        method="GET",
        fields=[
            SemanticField(path="body.name", inferred_type="STRING", confidence=0.95, entropy_score=0.3, example_value="Alice"),
        ],
        is_frozen=True,
        frozen_at=now,
        epistemic_state=EpistemicState.VERIFIED,
        provenance=["trace_a"],
    )
    replay = SemanticIRTrace(
        endpoint_template="/users/{id}",
        method="GET",
        fields=[
            SemanticField(path="body.name", inferred_type="STRING", confidence=0.95, entropy_score=0.3, example_value="Bob"),
        ],
        is_frozen=True,
        frozen_at=datetime.utcnow(),  # different timestamp
        epistemic_state=EpistemicState.CONTESTED,
        provenance=["trace_b"],
    )

    diff, violations = validator.compare(orig, replay)
    # Timestamps and example_values are stripped by canonicalization
    assert diff.replay_equivalence == "STRICT_EQUIVALENT"
    assert diff.structural_delta_score == 0.0


def test_auth_consistency_bearer_token_reuse():
    from pi_agent_chain.models import AuthConsistencyReport, NormalizedTrafficPacket, SemanticIRTrace, SemanticField
    from pi_agent_chain.verification.auth_consistency import AuthConsistencyValidator

    validator = AuthConsistencyValidator()

    # Two packets with same Bearer token
    packets = [
        NormalizedTrafficPacket(
            timestamp=1, method="GET", uri="/users/1",
            raw_headers=[("Authorization", "Bearer abc123xyz")],
            response_status=200,
        ),
        NormalizedTrafficPacket(
            timestamp=2, method="GET", uri="/users/2",
            raw_headers=[("Authorization", "Bearer abc123xyz")],
            response_status=200,
        ),
    ]
    traces = [
        SemanticIRTrace(endpoint_template="/users/1", method="GET", fields=[]),
        SemanticIRTrace(endpoint_template="/users/2", method="GET", fields=[]),
    ]

    report = validator.validate(traces, packets, execution_id="test_reuse")
    reuse_invs = [inv for inv in report.invariants if inv.invariant_type == "TOKEN_REUSE"]
    assert len(reuse_invs) == 1
    assert reuse_invs[0].confidence > 0.0


def test_auth_consistency_csrf_coupling():
    from pi_agent_chain.models import NormalizedTrafficPacket, SemanticIRTrace
    from pi_agent_chain.verification.auth_consistency import AuthConsistencyValidator

    validator = AuthConsistencyValidator()

    packets = [
        NormalizedTrafficPacket(
            timestamp=1, method="POST", uri="/transfer",
            raw_headers=[
                ("Cookie", "sessionid=abc123"),
                ("X-CSRF-Token", "u9f8a7s6d5"),
            ],
            response_status=200,
        ),
        NormalizedTrafficPacket(
            timestamp=2, method="POST", uri="/transfer",
            raw_headers=[
                ("Cookie", "sessionid=def456"),
                ("X-CSRF-Token", "z1x2c3v4b5"),
            ],
            response_status=200,
        ),
    ]
    traces = [
        SemanticIRTrace(endpoint_template="/transfer", method="POST", fields=[]),
        SemanticIRTrace(endpoint_template="/transfer", method="POST", fields=[]),
    ]

    report = validator.validate(traces, packets, execution_id="test_csrf")
    csrf_invs = [inv for inv in report.invariants if inv.invariant_type == "CSRF_COUPLING"]
    assert len(csrf_invs) == 1
    assert csrf_invs[0].confidence == 1.0  # perfect co-occurrence


def test_auth_consistency_session_rotation():
    from pi_agent_chain.models import NormalizedTrafficPacket, SemanticIRTrace
    from pi_agent_chain.verification.auth_consistency import AuthConsistencyValidator

    validator = AuthConsistencyValidator()

    packets = [
        NormalizedTrafficPacket(
            timestamp=1, method="GET", uri="/profile",
            raw_headers=[("Authorization", "Bearer token_a")],
            response_status=200,
        ),
        NormalizedTrafficPacket(
            timestamp=2, method="GET", uri="/profile",
            raw_headers=[("Authorization", "Bearer token_b")],
            response_status=200,
        ),
        NormalizedTrafficPacket(
            timestamp=3, method="GET", uri="/profile",
            raw_headers=[("Authorization", "Bearer token_c")],
            response_status=200,
        ),
    ]
    traces = [
        SemanticIRTrace(endpoint_template="/profile", method="GET", fields=[]),
        SemanticIRTrace(endpoint_template="/profile", method="GET", fields=[]),
        SemanticIRTrace(endpoint_template="/profile", method="GET", fields=[]),
    ]

    report = validator.validate(traces, packets, execution_id="test_rotation")
    rot_invs = [inv for inv in report.invariants if inv.invariant_type == "SESSION_ROTATION"]
    assert len(rot_invs) == 1
    assert rot_invs[0].rotation_class == "PER_REQUEST"
    assert rot_invs[0].confidence > 0.0


def test_auth_consistency_session_rotation_static():
    from pi_agent_chain.models import NormalizedTrafficPacket, SemanticIRTrace
    from pi_agent_chain.verification.auth_consistency import AuthConsistencyValidator

    validator = AuthConsistencyValidator()

    packets = [
        NormalizedTrafficPacket(
            timestamp=1, method="GET", uri="/profile",
            raw_headers=[("Authorization", "Bearer same_token")],
            response_status=200,
        ),
        NormalizedTrafficPacket(
            timestamp=2, method="GET", uri="/profile",
            raw_headers=[("Authorization", "Bearer same_token")],
            response_status=200,
        ),
    ]
    traces = [
        SemanticIRTrace(endpoint_template="/profile", method="GET", fields=[]),
        SemanticIRTrace(endpoint_template="/profile", method="GET", fields=[]),
    ]

    report = validator.validate(traces, packets, execution_id="test_static")
    rot_invs = [inv for inv in report.invariants if inv.invariant_type == "SESSION_ROTATION"]
    assert len(rot_invs) == 1
    assert rot_invs[0].rotation_class == "STATIC"


def test_auth_consistency_session_rotation_state_bound():
    from pi_agent_chain.models import NormalizedTrafficPacket, SemanticIRTrace
    from pi_agent_chain.verification.auth_consistency import AuthConsistencyValidator

    validator = AuthConsistencyValidator()

    packets = [
        NormalizedTrafficPacket(
            timestamp=1, method="GET", uri="/profile",
            raw_headers=[("Authorization", "Bearer token_a")],
            response_status=200,
        ),
        NormalizedTrafficPacket(
            timestamp=2, method="GET", uri="/profile",
            raw_headers=[("Authorization", "Bearer token_b")],
            response_status=401,
        ),
    ]
    traces = [
        SemanticIRTrace(endpoint_template="/profile", method="GET", fields=[]),
        SemanticIRTrace(endpoint_template="/profile", method="GET", fields=[]),
    ]

    report = validator.validate(traces, packets, execution_id="test_state")
    rot_invs = [inv for inv in report.invariants if inv.invariant_type == "SESSION_ROTATION"]
    assert len(rot_invs) == 1
    assert rot_invs[0].rotation_class == "STATE_BOUND"


def test_auth_consistency_auth_transition_401():
    from pi_agent_chain.models import NormalizedTrafficPacket, SemanticIRTrace
    from pi_agent_chain.verification.auth_consistency import AuthConsistencyValidator

    validator = AuthConsistencyValidator(min_binding_confidence=0.5)

    # Need 5+ packets to hit confidence threshold (5/5=1.0 >= 0.5)
    packets = [
        NormalizedTrafficPacket(
            timestamp=i, method="GET", uri="/admin",
            raw_headers=[("Authorization", "Bearer badtoken")],
            response_status=401 if i % 2 == 0 else 403,
        )
        for i in range(5)
    ]
    traces = [
        SemanticIRTrace(endpoint_template="/admin", method="GET", fields=[])
        for _ in range(5)
    ]

    report = validator.validate(traces, packets, execution_id="test_trans")
    trans_invs = [inv for inv in report.invariants if inv.invariant_type == "AUTH_TRANSITION"]
    assert len(trans_invs) == 1

    # Should generate governance violation because confidence >= threshold (5/5=1.0)
    violations = report.violations
    assert any(v.rule == "AUTH_TRANSITION_INVALIDATION" for v in violations)


def test_auth_consistency_evidence_bound_no_speculation():
    from pi_agent_chain.models import NormalizedTrafficPacket, SemanticIRTrace
    from pi_agent_chain.verification.auth_consistency import AuthConsistencyValidator

    validator = AuthConsistencyValidator()

    # Header named "X-Custom-Thing" with non-auth-looking value
    # Should NOT be classified as auth because value doesn't match patterns
    packets = [
        NormalizedTrafficPacket(
            timestamp=1, method="GET", uri="/public",
            raw_headers=[("X-Custom-Thing", "hello-world")],
            response_status=200,
        ),
    ]
    traces = [
        SemanticIRTrace(endpoint_template="/public", method="GET", fields=[]),
    ]

    report = validator.validate(traces, packets, execution_id="test_evidence")
    assert len(report.evidence) == 0  # No auth evidence extracted
    assert report.auth_field_count == 0


def test_auth_consistency_replay_survivability():
    from pi_agent_chain.models import NormalizedTrafficPacket, SemanticField, SemanticIRTrace
    from pi_agent_chain.verification.auth_consistency import AuthConsistencyValidator

    validator = AuthConsistencyValidator()

    packets = [
        NormalizedTrafficPacket(
            timestamp=1, method="GET", uri="/api/data",
            raw_headers=[("Authorization", "Bearer eyJhbGci...")],
            response_status=200,
        ),
    ]
    traces = [
        SemanticIRTrace(
            endpoint_template="/api/data", method="GET",
            fields=[SemanticField(path="header.authorization", inferred_type="JWT", confidence=0.95, entropy_score=0.8)],
        ),
    ]

    report = validator.validate(traces, packets, execution_id="test_replay")
    replay_invs = [inv for inv in report.invariants if inv.invariant_type == "REPLAY_SURVIVABILITY"]
    assert len(replay_invs) == 1
    assert replay_invs[0].epistemic_state == "OBSERVED"


def test_auth_consistency_no_auth_clean_traffic():
    from pi_agent_chain.models import NormalizedTrafficPacket, SemanticIRTrace
    from pi_agent_chain.verification.auth_consistency import AuthConsistencyValidator

    validator = AuthConsistencyValidator()

    packets = [
        NormalizedTrafficPacket(
            timestamp=1, method="GET", uri="/health",
            raw_headers=[("Accept", "application/json")],
            response_status=200,
        ),
    ]
    traces = [
        SemanticIRTrace(endpoint_template="/health", method="GET", fields=[]),
    ]

    report = validator.validate(traces, packets, execution_id="test_clean")
    assert len(report.evidence) == 0
    assert len(report.invariants) == 0
    assert len(report.violations) == 0
    assert report.token_entropy == 0.0


def test_auth_consistency_dependency_ordering_is_contested():
    from pi_agent_chain.models import NormalizedTrafficPacket, SemanticIRTrace
    from pi_agent_chain.verification.auth_consistency import AuthConsistencyValidator

    validator = AuthConsistencyValidator()

    # Multiple endpoints with auth evidence
    packets = [
        NormalizedTrafficPacket(
            timestamp=1, method="POST", uri="/login",
            raw_headers=[("Authorization", "Bearer token_a")],
            response_status=200,
        ),
        NormalizedTrafficPacket(
            timestamp=2, method="GET", uri="/profile",
            raw_headers=[("Authorization", "Bearer token_a")],
            response_status=200,
        ),
    ]
    traces = [
        SemanticIRTrace(endpoint_template="/login", method="POST", fields=[]),
        SemanticIRTrace(endpoint_template="/profile", method="GET", fields=[]),
    ]

    report = validator.validate(traces, packets, execution_id="test_order")
    order_invs = [inv for inv in report.invariants if inv.invariant_type == "DEPENDENCY_ORDERING"]
    assert len(order_invs) == 1
    assert order_invs[0].epistemic_state == "CONTESTED"
    assert len(order_invs[0].replay_confirmed_endpoints) == 0
    assert "TEMPORAL ONLY" in order_invs[0].description


def test_state_transition_fsm_basic():
    from pi_agent_chain.models import (
        AuthConsistencyReport, NormalizedTrafficPacket, SemanticIRTrace, EpistemicState
    )
    from pi_agent_chain.verification.state_transition import StateTransitionValidator

    validator = StateTransitionValidator()

    traces = [
        SemanticIRTrace(endpoint_template="/login", method="POST", fields=[]),
        SemanticIRTrace(endpoint_template="/profile", method="GET", fields=[]),
    ]
    packets = [
        NormalizedTrafficPacket(timestamp=1, method="POST", uri="/login", raw_headers=[], response_status=200),
        NormalizedTrafficPacket(timestamp=2, method="GET", uri="/profile", raw_headers=[], response_status=200),
    ]
    auth_report = AuthConsistencyReport(report_id="test")

    fsm, violations = validator.extract_fsm(traces, packets, auth_report, execution_id="test_basic")
    assert fsm.node_count() == 2
    assert fsm.edge_count() == 1
    assert fsm.nodes[0].endpoint_template == "/login"
    assert fsm.nodes[1].endpoint_template == "/profile"
    assert fsm.edges[0].epistemic_state == EpistemicState.OBSERVED
    assert violations == []  # no bounds exceeded for tiny FSM


def test_state_transition_fsm_bounds():
    from pi_agent_chain.models import AuthConsistencyReport, NormalizedTrafficPacket, SemanticIRTrace
    from pi_agent_chain.verification.state_transition import StateTransitionValidator

    validator = StateTransitionValidator()

    traces = [
        SemanticIRTrace(endpoint_template=f"/endpoint{i}", method="GET", fields=[])
        for i in range(100)
    ]
    packets = [
        NormalizedTrafficPacket(timestamp=i, method="GET", uri=f"/endpoint{i}", raw_headers=[], response_status=200)
        for i in range(100)
    ]
    auth_report = AuthConsistencyReport(report_id="test")

    fsm, violations = validator.extract_fsm(traces, packets, auth_report, execution_id="test_bounds")
    assert fsm.node_count() <= validator.bounds.max_fsm_nodes  # bounded
    # Should have NODE_OVERFLOW violation because 100 > 64
    assert any(v.rule == "FSM_NODE_OVERFLOW" for v in violations)


def test_state_transition_fsm_replay_promotion():
    from pi_agent_chain.models import (
        AuthConsistencyReport, NormalizedTrafficPacket, SemanticIRTrace, EpistemicState
    )
    from pi_agent_chain.verification.state_transition import StateTransitionValidator

    validator = StateTransitionValidator()

    traces = [
        SemanticIRTrace(endpoint_template="/login", method="POST", fields=[]),
        SemanticIRTrace(endpoint_template="/profile", method="GET", fields=[]),
    ]
    packets = [
        NormalizedTrafficPacket(timestamp=1, method="POST", uri="/login", raw_headers=[], response_status=200),
        NormalizedTrafficPacket(timestamp=2, method="GET", uri="/profile", raw_headers=[], response_status=200),
    ]
    auth_report = AuthConsistencyReport(report_id="test")

    fsm, violations = validator.extract_fsm(traces, packets, auth_report, execution_id="test_replay")
    edge = fsm.edges[0]
    assert edge.epistemic_state == EpistemicState.OBSERVED
    assert edge.replay_confirmed_count == 0
    assert len(edge.constraints) == 1
    assert edge.constraints[0].constraint_type == "REPLAY_REQUIRED"


def test_state_transition_fsm_no_self_loops():
    from pi_agent_chain.models import AuthConsistencyReport, NormalizedTrafficPacket, SemanticIRTrace
    from pi_agent_chain.verification.state_transition import StateTransitionValidator

    validator = StateTransitionValidator()

    traces = [
        SemanticIRTrace(endpoint_template="/login", method="POST", fields=[]),
        SemanticIRTrace(endpoint_template="/login", method="POST", fields=[]),
    ]
    packets = [
        NormalizedTrafficPacket(timestamp=1, method="POST", uri="/login", raw_headers=[], response_status=200),
        NormalizedTrafficPacket(timestamp=2, method="POST", uri="/login", raw_headers=[], response_status=200),
    ]
    auth_report = AuthConsistencyReport(report_id="test")

    fsm, violations = validator.extract_fsm(traces, packets, auth_report, execution_id="test_self")
    assert fsm.node_count() == 1  # deduplicated
    assert fsm.edge_count() == 0  # no self-loops


def build_test_artifact(field_type: str = "UUIDv4", path: str = "response.body.id") -> tuple:
    """Helper to build SemanticArtifact + SemanticIRTrace for quorum tests."""
    from pi_agent_chain.models import SemanticField, SemanticIRTrace, EpistemicState
    from pi_agent_chain.artifact_registry import SemanticArtifact
    import json

    trace = SemanticIRTrace(
        endpoint_template="/api/v1/test",
        method="GET",
        fields=[SemanticField(path=path, inferred_type=field_type, confidence=0.95, entropy_score=0.1)],
        epistemic_state=EpistemicState.INFERRED,
    )
    payload = trace.model_dump()
    artifact = SemanticArtifact(
        artifact_id="artifact_001",
        artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.INFERRED,
        semantic_hash="abc123",
        generated_by="SemanticTyperNode",
        payload_json=json.dumps(payload),
        provenance=["test"],
    )
    return artifact, trace


def test_semantic_quorum_replay_confirmed_promotion():
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.artifact_registry import SemanticArtifact
    from pi_agent_chain.verification.semantic_quorum import SemanticQuorum
    import json

    # Build REPLAY_CONFIRMED artifact
    trace = SemanticIRTrace(
        endpoint_template="/api/v1/test",
        method="GET",
        fields=[SemanticField(path="response.body.id", inferred_type="UUIDv4", confidence=0.95, entropy_score=0.1)],
        epistemic_state=EpistemicState.REPLAY_CONFIRMED,
    )
    artifact = SemanticArtifact(
        artifact_id="artifact_rc",
        artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.REPLAY_CONFIRMED,
        semantic_hash="hash_rc",
        generated_by="ReplayValidator",
        payload_json=json.dumps(trace.model_dump()),
        provenance=["replay:test"],
    )

    quorum = SemanticQuorum()
    report = quorum.execute([artifact], execution_id="test_promote")
    assert report.quorum_reached
    assert len(report.intersections) == 1
    assert report.intersections[0].consensus_replay_confirmed is True
    # Should have REPLAY_CONFIRMED promotion entry
    assert any(p["to_state"] == EpistemicState.REPLAY_CONFIRMED for p in report.promotions)


def test_semantic_quorum_contested_collision():
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.artifact_registry import SemanticArtifact
    from pi_agent_chain.verification.semantic_quorum import SemanticQuorum
    import json

    # Two artifacts with CONFLICTING types on SAME path
    trace1 = SemanticIRTrace(
        endpoint_template="/api/v1/test",
        method="GET",
        fields=[SemanticField(path="response.body.id", inferred_type="UUIDv4", confidence=0.95, entropy_score=0.1)],
        epistemic_state=EpistemicState.INFERRED,
    )
    trace2 = SemanticIRTrace(
        endpoint_template="/api/v1/test",
        method="GET",
        fields=[SemanticField(path="response.body.id", inferred_type="STRING", confidence=0.92, entropy_score=0.1)],
        epistemic_state=EpistemicState.INFERRED,
    )
    a1 = SemanticArtifact(
        artifact_id="a1", artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.INFERRED, semantic_hash="h1",
        generated_by="SemanticTyperNode", payload_json=json.dumps(trace1.model_dump()), provenance=[],
    )
    a2 = SemanticArtifact(
        artifact_id="a2", artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.INFERRED, semantic_hash="h2",
        generated_by="SemanticTyperNode", payload_json=json.dumps(trace2.model_dump()), provenance=[],
    )

    quorum = SemanticQuorum()
    report = quorum.execute([a1, a2], execution_id="test_conflict")
    assert len(report.conflict_sets) == 1
    assert report.conflict_sets[0].conflict_type == "TYPE_MISMATCH"
    assert report.conflict_sets[0].epistemic_state == EpistemicState.CONTESTED
    # Strict consensus: disagreement means zero intersections, not picking a winner
    assert len(report.intersections) == 0


def test_semantic_quorum_entropy_reduction_monotonicity():
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.artifact_registry import SemanticArtifact
    from pi_agent_chain.verification.semantic_quorum import SemanticQuorum
    import json

    trace = SemanticIRTrace(
        endpoint_template="/api/v1/test", method="GET",
        fields=[
            SemanticField(path="a", inferred_type="UUIDv4", confidence=0.95, entropy_score=0.1),
            SemanticField(path="b", inferred_type="STRING", confidence=0.95, entropy_score=0.1),
        ],
        epistemic_state=EpistemicState.INFERRED,
    )
    artifact = SemanticArtifact(
        artifact_id="a1", artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.INFERRED, semantic_hash="h1",
        generated_by="SemanticTyperNode", payload_json=json.dumps(trace.model_dump()), provenance=[],
    )

    quorum = SemanticQuorum()
    report = quorum.execute([artifact], execution_id="test_entropy")
    # Single trace with 2 distinct types: entropy_before > entropy_after should not increase
    assert report.entropy_delta <= 0.001  # allow tiny floating-point noise
    assert not report.violations


def test_semantic_quorum_overflow_protection():
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.artifact_registry import SemanticArtifact
    from pi_agent_chain.verification.semantic_quorum import SemanticQuorum
    import json

    artifacts = []
    for i in range(550):
        trace = SemanticIRTrace(
            endpoint_template=f"/api/v1/endpoint{i}", method="GET",
            fields=[SemanticField(path=f"field_{i}", inferred_type="STRING", confidence=0.5, entropy_score=0.5)],
            epistemic_state=EpistemicState.INFERRED,
        )
        artifacts.append(SemanticArtifact(
            artifact_id=f"a{i}", artifact_type="SemanticIRTrace",
            epistemic_state=EpistemicState.INFERRED, semantic_hash=f"h{i}",
            generated_by="SemanticTyperNode", payload_json=json.dumps(trace.model_dump()), provenance=[],
        ))

    quorum = SemanticQuorum()
    report = quorum.execute(artifacts, execution_id="test_overflow")
    assert report.bounded_truncated
    assert any(v.rule == "QUORUM_MAX_CLAIMS_EXCEEDED" for v in report.violations)


def test_semantic_quorum_provenance_preservation():
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.artifact_registry import SemanticArtifact
    from pi_agent_chain.verification.semantic_quorum import SemanticQuorum
    import json

    trace = SemanticIRTrace(
        endpoint_template="/api/v1/test", method="GET",
        fields=[SemanticField(path="x", inferred_type="UUIDv4", confidence=0.95, entropy_score=0.1)],
        epistemic_state=EpistemicState.INFERRED,
    )
    artifact = SemanticArtifact(
        artifact_id="prov_a1", artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.INFERRED, semantic_hash="h1",
        generated_by="SemanticTyperNode", payload_json=json.dumps(trace.model_dump()),
        provenance=["trace:root", "packet:p1"],
    )

    quorum = SemanticQuorum()
    report = quorum.execute([artifact], execution_id="test_provenance")
    claim = report.claims[0]
    assert "prov_a1" in claim.provenance_chain
    assert artifact.artifact_id == claim.artifact_id
    assert artifact.generated_by == claim.worker_id


def test_semantic_quorum_replay_consistency():
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.artifact_registry import SemanticArtifact
    from pi_agent_chain.verification.semantic_quorum import SemanticQuorum
    import json

    trace1 = SemanticIRTrace(
        endpoint_template="/api/v1/test", method="GET",
        fields=[SemanticField(path="y", inferred_type="UUIDv4", confidence=0.95, entropy_score=0.1)],
        epistemic_state=EpistemicState.OBSERVED,
    )
    trace2 = SemanticIRTrace(
        endpoint_template="/api/v1/test", method="GET",
        fields=[SemanticField(path="y", inferred_type="UUIDv4", confidence=0.94, entropy_score=0.1)],
        epistemic_state=EpistemicState.OBSERVED,
    )
    a1 = SemanticArtifact(
        artifact_id="rc1", artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.OBSERVED, semantic_hash="h1",
        generated_by="IngressParser", payload_json=json.dumps(trace1.model_dump()), provenance=[],
    )
    a2 = SemanticArtifact(
        artifact_id="rc2", artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.OBSERVED, semantic_hash="h2",
        generated_by="IngressParser", payload_json=json.dumps(trace2.model_dump()), provenance=[],
    )

    quorum = SemanticQuorum()
    report = quorum.execute([a1, a2], execution_id="test_consistent")
    assert len(report.intersections) == 1
    inter = report.intersections[0]
    assert inter.intersected_type == "UUIDv4"
    assert len(inter.agreement_claim_ids) == 2


def test_semantic_quorum_monotonic_promotion():
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.artifact_registry import SemanticArtifact
    from pi_agent_chain.verification.semantic_quorum import SemanticQuorum
    import json

    trace = SemanticIRTrace(
        endpoint_template="/api/v1/test", method="GET",
        fields=[SemanticField(path="z", inferred_type="STRING", confidence=0.95, entropy_score=0.1)],
        epistemic_state=EpistemicState.OBSERVED,
    )
    artifact = SemanticArtifact(
        artifact_id="mono_a1", artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.OBSERVED, semantic_hash="h1",
        generated_by="IngressParser", payload_json=json.dumps(trace.model_dump()), provenance=[],
    )

    quorum = SemanticQuorum()
    report = quorum.execute([artifact], execution_id="test_mono")
    # OBSERVED -> INFERRED promotion should occur because authority >= 0.4
    promos = [p for p in report.promotions if p["property_path"] == "z"]
    assert len(promos) >= 1
    assert promos[0]["from_state"] == EpistemicState.OBSERVED
    assert promos[0]["to_state"] == EpistemicState.INFERRED


def test_semantic_quorum_reject_unsupported_expansion():
    from pi_agent_chain.models import EpistemicState, SemanticField, SemanticIRTrace
    from pi_agent_chain.artifact_registry import SemanticArtifact
    from pi_agent_chain.verification.semantic_quorum import SemanticQuorum
    import json

    # OBSERVED claim with low confidence -> authority halved to 0.2, below threshold -> rejected
    trace = SemanticIRTrace(
        endpoint_template="/api/v1/test", method="GET",
        fields=[SemanticField(path="guess", inferred_type="UNKNOWN_STR", confidence=0.1, entropy_score=0.9)],
        epistemic_state=EpistemicState.OBSERVED,
    )
    artifact = SemanticArtifact(
        artifact_id="low_a1", artifact_type="SemanticIRTrace",
        epistemic_state=EpistemicState.OBSERVED, semantic_hash="h1",
        generated_by="IngressParser", payload_json=json.dumps(trace.model_dump()), provenance=[],
    )

    quorum = SemanticQuorum()
    report = quorum.execute([artifact], execution_id="test_reject")
    # Low confidence means authority drops below threshold -> claim rejected
    assert len(report.rejected_claims) >= 1


def test_entropy_analysis_structural_measurement():
    from pi_agent_chain.models import (
        EpistemicState, SemanticClaim, SemanticField, SemanticIntersection,
        SemanticQuorumReport, SemanticIRTrace,
    )
    from pi_agent_chain.verification.entropy_analysis import EntropyAnalysisValidator

    # Single path, single type -> low structural entropy
    claim = SemanticClaim(
        claim_id="c1", property_path="body.id", semantic_type="UUIDv4",
        confidence_score=0.95, artifact_id="a1", trace_id="t1", packet_id="",
        worker_id="w1", source_epistemic_state=EpistemicState.OBSERVED,
        replay_confirmed=True, provenance_chain=["a1"], authority_weight=1.0,
    )
    quorum = SemanticQuorumReport(
        report_id="r1", execution_id="e1",
        claims=[claim],
        intersections=[SemanticIntersection(
            intersection_id="i1", property_path="body.id",
            intersected_type="UUIDv4", intersected_confidence=0.95,
            agreement_claim_ids=["c1"], total_authority_sum=1.0,
            consensus_replay_confirmed=True,
        )],
    )
    analyzer = EntropyAnalysisValidator()
    report = analyzer.analyze(quorum, fsm=None, auth_report=None, execution_id="e1")
    # Single type on single path = low structural entropy
    assert report.snapshot.structural_entropy < 0.3


def test_entropy_analysis_semantic_conflict_entropy():
    from pi_agent_chain.models import (
        EpistemicState, SemanticClaim, SemanticConflictSet, SemanticQuorumReport,
    )
    from pi_agent_chain.verification.entropy_analysis import EntropyAnalysisValidator

    # Conflicting claims create high semantic entropy
    c1 = SemanticClaim(
        claim_id="c1", property_path="body.id", semantic_type="UUIDv4",
        confidence_score=0.95, artifact_id="a1", trace_id="t1", packet_id="",
        worker_id="w1", source_epistemic_state=EpistemicState.INFERRED,
        replay_confirmed=False, provenance_chain=["a1"], authority_weight=0.8,
    )
    c2 = SemanticClaim(
        claim_id="c2", property_path="body.id", semantic_type="STRING",
        confidence_score=0.90, artifact_id="a2", trace_id="t2", packet_id="",
        worker_id="w1", source_epistemic_state=EpistemicState.INFERRED,
        replay_confirmed=False, provenance_chain=["a2"], authority_weight=0.8,
    )
    quorum = SemanticQuorumReport(
        report_id="r1", execution_id="e1",
        claims=[c1, c2],
        conflict_sets=[SemanticConflictSet(
            conflict_id="x1", property_path="body.id",
            conflicting_claim_ids=["c1", "c2"],
            conflict_type="TYPE_MISMATCH", description="conflict",
            max_confidence=0.95,
        )],
    )
    analyzer = EntropyAnalysisValidator()
    report = analyzer.analyze(quorum, fsm=None, auth_report=None, execution_id="e1")
    # Conflict + no intersections = high semantic entropy
    assert report.snapshot.semantic_entropy > 0.3
    assert len(report.drift_signatures) >= 1


def test_entropy_analysis_replay_entropy_from_auth():
    from pi_agent_chain.models import (
        AuthConsistencyReport, AuthEvidence, AuthInvariant,
        EpistemicState, GovernanceViolation,
        SemanticClaim, SemanticQuorumReport,
    )
    from pi_agent_chain.verification.entropy_analysis import EntropyAnalysisValidator

    # Auth violation increases replay entropy
    auth = AuthConsistencyReport(
        report_id="ar1", execution_id="e1",
        invariants=[AuthInvariant(
            invariant_id="inv1", invariant_type="REPLAY_SURVIVABILITY",
            description="replay", confidence=0.9, evidence_refs=["e1"],
            affected_endpoints=["/api/test"],
        )],
        evidence=[AuthEvidence(
            evidence_id="e1", trace_id="t1", packet_id="p1",
            evidence_type="BEARER_HEADER", field_path="header.Authorization",
            carrier="HEADER", observed_value_hash="abc", status_code=200,
        )],
        violations=[GovernanceViolation(
            violation_id="v1", rule="AUTH_INVARIANT_BROKEN",
            worker_id="auth_validator", root_goal_id="e1", severity="ERROR",
            context={}, action_taken="HALT",
        )],
    )
    quorum = SemanticQuorumReport(
        report_id="r1", execution_id="e1",
        claims=[SemanticClaim(
            claim_id="c1", property_path="x", semantic_type="STRING",
            confidence_score=0.5, artifact_id="a1", trace_id="t1", packet_id="",
            worker_id="w1", source_epistemic_state=EpistemicState.OBSERVED,
            replay_confirmed=False, provenance_chain=["a1"], authority_weight=0.4,
        )],
    )
    analyzer = EntropyAnalysisValidator()
    report = analyzer.analyze(quorum, fsm=None, auth_report=auth, execution_id="e1")
    # Auth violation should push replay entropy up
    assert report.snapshot.replay_entropy > 0.0
    assert report.replay_stability.auth_mutation_count >= 1


def test_entropy_analysis_topological_from_fsm():
    from pi_agent_chain.models import (
        EpistemicState, ProtocolStateMachine, SemanticQuorumReport,
        StateNode, TransitionEdge, TransitionConstraint,
    )
    from pi_agent_chain.verification.entropy_analysis import EntropyAnalysisValidator

    fsm = ProtocolStateMachine(
        fsm_id="fsm1", execution_id="e1",
        nodes=[
            StateNode(node_id="n1", endpoint_template="/login", method="POST", epistemic_state=EpistemicState.OBSERVED),
            StateNode(node_id="n2", endpoint_template="/profile", method="GET", epistemic_state=EpistemicState.OBSERVED),
        ],
        edges=[
            TransitionEdge(
                edge_id="e1", from_node="n1", to_node="n2",
                observed_count=1, replay_confirmed=False,
                constraints=[TransitionConstraint(constraint_type="REPLAY_REQUIRED", description="needs replay")],
            ),
        ],
        max_nodes=64, max_edges=256, max_fanout=8, max_depth=6,
    )
    quorum = SemanticQuorumReport(report_id="r1", execution_id="e1", claims=[])
    analyzer = EntropyAnalysisValidator()
    report = analyzer.analyze(quorum, fsm=fsm, auth_report=None, execution_id="e1")
    # Unconfirmed edge ratio = 1.0 -> some topological entropy
    assert report.snapshot.topological_entropy > 0.0
    assert report.topological_entropy.unconfirmed_edge_ratio == 1.0


def test_entropy_analysis_convergence_scoring():
    from pi_agent_chain.models import (
        EpistemicState, SemanticClaim, SemanticIntersection, SemanticQuorumReport,
    )
    from pi_agent_chain.verification.entropy_analysis import EntropyAnalysisValidator

    # Clean replay-confirmed intersection -> high convergence
    c = SemanticClaim(
        claim_id="c1", property_path="id", semantic_type="UUIDv4",
        confidence_score=0.98, artifact_id="a1", trace_id="t1", packet_id="",
        worker_id="w1", source_epistemic_state=EpistemicState.REPLAY_CONFIRMED,
        replay_confirmed=True, provenance_chain=["a1"], authority_weight=1.0,
    )
    quorum = SemanticQuorumReport(
        report_id="r1", execution_id="e1",
        claims=[c],
        intersections=[SemanticIntersection(
            intersection_id="i1", property_path="id",
            intersected_type="UUIDv4", intersected_confidence=0.98,
            agreement_claim_ids=["c1"], total_authority_sum=1.0,
            consensus_replay_confirmed=True,
        )],
    )
    analyzer = EntropyAnalysisValidator()
    report = analyzer.analyze(quorum, fsm=None, auth_report=None, execution_id="e1")
    # High replay confirmation, low entropy -> high convergence
    assert report.convergence.score > 0.8
    assert report.convergence.confidence_bound > 0.8


def test_entropy_analysis_delta_regression():
    from pi_agent_chain.models import (
        EntropySnapshot, EpistemicState, SemanticClaim, SemanticIntersection,
        SemanticQuorumReport,
    )
    from pi_agent_chain.verification.entropy_analysis import EntropyAnalysisValidator

    prior = EntropySnapshot(
        snapshot_id="s1", execution_id="e1",
        structural_entropy=0.1, semantic_entropy=0.1, replay_entropy=0.1,
        temporal_entropy=0.0, topological_entropy=0.1,
        composite_entropy=0.1, evidence_count=2,
    )
    # Current state with MORE conflicts -> higher entropy
    c1 = SemanticClaim(
        claim_id="c1", property_path="id", semantic_type="UUIDv4",
        confidence_score=0.95, artifact_id="a1", trace_id="t1", packet_id="",
        worker_id="w1", source_epistemic_state=EpistemicState.INFERRED,
        replay_confirmed=False, provenance_chain=["a1"], authority_weight=0.8,
    )
    c2 = SemanticClaim(
        claim_id="c2", property_path="id", semantic_type="STRING",
        confidence_score=0.90, artifact_id="a2", trace_id="t2", packet_id="",
        worker_id="w1", source_epistemic_state=EpistemicState.INFERRED,
        replay_confirmed=False, provenance_chain=["a2"], authority_weight=0.8,
    )
    quorum = SemanticQuorumReport(
        report_id="r2", execution_id="e1",
        claims=[c1, c2],
        conflict_sets=[],
    )
    analyzer = EntropyAnalysisValidator()
    report = analyzer.analyze(quorum, fsm=None, auth_report=None, execution_id="e1", prior_snapshot=prior)
    assert report.delta is not None
    # Semantic entropy should have increased -> REGRESSING
    assert report.delta.semantic_delta > 0.0
    assert report.delta.trend == "REGRESSING"
    assert "semantic" in report.delta.regression_dimensions


def test_entropy_analysis_window_bounded():
    from pi_agent_chain.models import SemanticQuorumReport
    from pi_agent_chain.verification.entropy_analysis import EntropyAnalysisValidator

    analyzer = EntropyAnalysisValidator()
    quorum = SemanticQuorumReport(report_id="r", execution_id="e", claims=[])

    # Feed 40 snapshots (exceeds max_entropy_window_size=32)
    for i in range(40):
        report = analyzer.analyze(quorum, fsm=None, auth_report=None, execution_id=f"e{i}")

    window = report.stability_window
    assert window is not None
    assert len(window.snapshots) <= analyzer.bounds.max_entropy_window_size


def test_entropy_analysis_drift_detection():
    from pi_agent_chain.models import (
        EpistemicState, SemanticClaim, SemanticConflictSet, SemanticQuorumReport,
    )
    from pi_agent_chain.verification.entropy_analysis import EntropyAnalysisValidator

    # High disagreement density triggers drift signature
    # 5 claims on same path with conflicts -> disagreement_density = 1.0 (5/5)
    claims = []
    for i in range(5):
        claims.append(SemanticClaim(
            claim_id=f"c{i}", property_path="body.id",
            semantic_type="STRING" if i % 2 == 0 else "INTEGER",
            confidence_score=0.6, artifact_id=f"a{i}", trace_id="t1", packet_id="",
            worker_id="w1", source_epistemic_state=EpistemicState.INFERRED,
            replay_confirmed=False, provenance_chain=[f"a{i}"], authority_weight=0.8,
        ))
    quorum = SemanticQuorumReport(
        report_id="r1", execution_id="e1",
        claims=claims,
        conflict_sets=[
            SemanticConflictSet(
                conflict_id="x1", property_path="body.id",
                conflicting_claim_ids=["c0", "c1"],
                conflict_type="TYPE_MISMATCH", description="conflict",
                max_confidence=0.6,
            ),
            SemanticConflictSet(
                conflict_id="x2", property_path="body.id",
                conflicting_claim_ids=["c2", "c3"],
                conflict_type="TYPE_MISMATCH", description="conflict2",
                max_confidence=0.6,
            ),
        ],
    )
    analyzer = EntropyAnalysisValidator()
    report = analyzer.analyze(quorum, fsm=None, auth_report=None, execution_id="e1")
    # Should detect semantic fragmentation drift
    semantic_drifts = [d for d in report.drift_signatures if d.pattern_type == "SEMANTIC_FRAGMENTATION"]
    assert len(semantic_drifts) >= 1


def test_entropy_analysis_composite_bounded():
    from pi_agent_chain.models import SemanticQuorumReport
    from pi_agent_chain.verification.entropy_analysis import EntropyAnalysisValidator

    # Empty quorum -> all entropies = 0 -> composite = 0
    quorum = SemanticQuorumReport(report_id="r1", execution_id="e1", claims=[])
    analyzer = EntropyAnalysisValidator()
    report = analyzer.analyze(quorum, fsm=None, auth_report=None, execution_id="e1")
    # With empty state, all dimensions should be 0
    assert report.snapshot.structural_entropy == 0.0
    assert report.snapshot.semantic_entropy == 0.0
    assert report.snapshot.replay_entropy == 0.0
    assert report.snapshot.temporal_entropy == 0.0
    assert report.snapshot.topological_entropy == 0.0
    assert report.snapshot.composite_entropy == 0.0
    assert report.snapshot.composite_entropy <= 1.0


def test_entropy_analysis_pipeline_integration():
    from pi_agent_chain.ledger import StateLedger
    from pi_agent_chain.pipeline import PipelineDriver

    req = "GET /api/v1/users HTTP/1.1\nHost: api.example.com\n\n"
    resp = 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"id":"550e8400-e29b-41d4-a716-446655440000"}'
    ledger = StateLedger(":memory:")
    driver = PipelineDriver(ledger=ledger, base_url="https://api.example.com")
    result = driver.run([(req, resp)])

    assert "entropy" in result
    entropy = result["entropy"]
    assert "snapshot" in entropy
    assert "convergence" in entropy
    assert "semantic_variance" in entropy
    assert "replay_stability" in entropy
