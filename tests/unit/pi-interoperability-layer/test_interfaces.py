"""Tests for runtime interface governance."""

from __future__ import annotations

from pi_interoperability_layer.interfaces import (
    ProvenanceChain,
    ReplaySafeRouter,
    RuntimeMessage,
    WorkerInputEnvelope,
    WorkerOutputEnvelope,
)


def test_worker_input_envelope_identity_hash() -> None:
    env = WorkerInputEnvelope(
        envelope_id="env1",
        target_runtime="pi-semantic-validator",
        operation="VALIDATE",
        artifacts=[{"type": "trace"}],
        policy_ref="policy.json",
        strict=True,
    )
    h1 = env.compute_identity_hash()
    h2 = env.compute_identity_hash()
    assert h1 == h2
    assert len(h1) == 64


def test_worker_output_envelope_output_hash() -> None:
    out = WorkerOutputEnvelope(
        envelope_id="out1",
        input_envelope_id="env1",
        target_runtime="pi-semantic-validator",
        operation="VALIDATE",
        status="SUCCESS",
        result={"passed": True},
    )
    h1 = out.compute_output_hash()
    h2 = out.compute_output_hash()
    assert h1 == h2
    assert len(h1) == 64


def test_runtime_message_provenance_hash() -> None:
    msg = RuntimeMessage(
        message_id="m1",
        message_type="ARTIFACT_HANDOFF",
        source_runtime="pi-semantic-recon",
        target_runtime="pi-semantic-validator",
        envelope={},
        provenance_chain=["m0"],
        sequence_number=1,
    )
    h = msg.compute_provenance_hash()
    assert len(h) == 64


def test_provenance_chain_append_and_verify() -> None:
    chain = ProvenanceChain(chain_id="pc1")
    updated = chain.append_step(
        runtime="recon",
        envelope_id="env1",
        artifact_fingerprint="fp1",
    )
    assert len(updated.runtime_sequence) == 1
    assert updated.verify_continuity() is True
    # Append again
    updated2 = updated.append_step(
        runtime="validator",
        envelope_id="env2",
        artifact_fingerprint="fp2",
    )
    assert len(updated2.runtime_sequence) == 2
    assert updated2.verify_continuity() is True


def test_replay_safe_router_allowed() -> None:
    router = ReplaySafeRouter(
        allowed_routes={"recon": ["validator", "diff"]},
        replay_safe_routes={"recon": ["validator"]},
    )
    msg = RuntimeMessage(
        message_id="m1",
        message_type="ARTIFACT_HANDOFF",
        source_runtime="recon",
        target_runtime="validator",
        envelope={},
        sequence_number=1,
    )
    assert router.route(msg) == "ALLOWED"
    assert router.is_replay_safe("recon", "validator") is True


def test_replay_safe_router_forbidden() -> None:
    router = ReplaySafeRouter(
        allowed_routes={"recon": ["validator"]},
        replay_safe_routes={"recon": ["validator"]},
    )
    msg = RuntimeMessage(
        message_id="m1",
        message_type="ARTIFACT_HANDOFF",
        source_runtime="recon",
        target_runtime="unauthorized",
        envelope={},
        sequence_number=1,
    )
    assert router.route(msg) == "FORBIDDEN"


def test_replay_safe_router_requires_verification() -> None:
    router = ReplaySafeRouter(
        allowed_routes={"recon": ["validator", "diff"]},
        replay_safe_routes={"recon": ["validator"]},
    )
    msg = RuntimeMessage(
        message_id="m1",
        message_type="ARTIFACT_HANDOFF",
        source_runtime="recon",
        target_runtime="diff",
        envelope={},
        sequence_number=1,
    )
    assert router.route(msg) == "REQUIRES_REPLAY_VERIFICATION"
    assert router.is_replay_safe("recon", "diff") is False
