"""Test suite for pi-semantic-validator policy schema and loader."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from pi_semantic_validator.policy import (
    ArchitecturePolicy,
    BlastRadiusLimit,
    ForbiddenImportRule,
    LayerDefinition,
    LayerRule,
    MutationRule,
    ReplayRule,
    StateWriterRule,
    TrustBoundaryRule,
    TrustZone,
    _glob_match,
    load_policy,
)


def test_glob_match_exact():
    assert _glob_match("/api/v1/users", "/api/v1/users")


def test_glob_match_star():
    assert _glob_match("/api/v1/users/123", "/api/v1/users/*")
    assert _glob_match("/api/v1/users", "/api/v1/*")


def test_glob_match_no_match():
    assert not _glob_match("/api/v2/users", "/api/v1/*")


def test_policy_hash_determinism():
    p = ArchitecturePolicy(
        policy_id="test",
        trust_zones=[TrustZone(zone_id="public", endpoint_patterns=["/public/*"])],
    )
    h1 = p.compute_hash()
    h2 = p.compute_hash()
    assert h1 == h2


def test_load_policy_roundtrip():
    policy = ArchitecturePolicy(
        policy_id="prod-policy-001",
        policy_version="1.0.0",
        description="Production policy",
        global_fail_closed=True,
        trust_zones=[
            TrustZone(
                zone_id="public",
                endpoint_patterns=["/public/*", "/login", "/register"],
                service_patterns=["web-public"],
            ),
            TrustZone(
                zone_id="internal",
                endpoint_patterns=["/api/*", "/admin/*"],
                service_patterns=["api-service"],
            ),
        ],
        trust_boundary_rules=[
            TrustBoundaryRule(
                rule_id="no-public-to-internal",
                from_zone="public",
                to_zone="internal",
                action="FORBIDDEN",
            )
        ],
        layers=[
            LayerDefinition(
                layer_id="frontend",
                endpoint_patterns=["/public/*"],
                forbidden_importers=["backend"],
            ),
            LayerDefinition(
                layer_id="backend",
                endpoint_patterns=["/api/*"],
            ),
        ],
        layer_rules=[
            LayerRule(
                rule_id="frontend-no-backend",
                from_layer="frontend",
                to_layer="backend",
                action="FORBIDDEN",
            )
        ],
        mutation_rules=[
            MutationRule(
                rule_id="api-mutation",
                endpoint_pattern="/api/*",
                methods=["POST", "PUT", "DELETE"],
                allowed_mutation_classes=["STATEFUL_MUTATION", "DESTRUCTIVE_MUTATION"],
                requires_auth_for_mutation=True,
            )
        ],
        replay_rules=[
            ReplayRule(
                rule_id="api-replay",
                endpoint_pattern="/api/*",
                methods=["GET"],
                required_replay_class="IDEMPOTENT",
                production_replay_prohibited=False,
            ),
            ReplayRule(
                rule_id="admin-replay",
                endpoint_pattern="/admin/*",
                methods=["POST", "DELETE"],
                required_replay_class="NON_REPLAYABLE",
                production_replay_prohibited=True,
                sandbox_required=True,
            ),
        ],
        blast_radius_limits=BlastRadiusLimit(
            max_dependencies_per_endpoint=8,
            max_cross_service_edges=16,
        ),
        state_writer_rules=[
            StateWriterRule(
                rule_id="backend-writes",
                layer_id="backend",
                allowed_writers=["postgres", "redis"],
                fail_closed=True,
            )
        ],
        forbidden_import_rules=[
            ForbiddenImportRule(
                rule_id="frontend-no-os",
                layer_id="frontend",
                forbidden_modules=["os", "sys"],
                is_critical=True,
            )
        ],
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(policy.model_dump(), f)
        path = f.name

    loaded = load_policy(path)
    assert loaded.policy_id == "prod-policy-001"
    assert loaded.global_fail_closed is True
    assert len(loaded.trust_zones) == 2
    assert len(loaded.mutation_rules) == 1
    Path(path).unlink()


def test_duplicate_zone_ids_raise():
    with pytest.raises(ValueError):
        ArchitecturePolicy(
            policy_id="bad",
            trust_zones=[
                TrustZone(zone_id="dup"),
                TrustZone(zone_id="dup"),
            ],
        )


def test_get_zone_for_endpoint():
    policy = ArchitecturePolicy(
        policy_id="test",
        trust_zones=[
            TrustZone(zone_id="public", endpoint_patterns=["/public/*"]),
            TrustZone(zone_id="internal", endpoint_patterns=["/api/*"]),
        ],
    )
    zone = policy.get_zone_for_endpoint("/public/login")
    assert zone is not None
    assert zone.zone_id == "public"


def test_get_layer_for_endpoint():
    policy = ArchitecturePolicy(
        policy_id="test",
        layers=[
            LayerDefinition(layer_id="frontend", endpoint_patterns=["/public/*"]),
            LayerDefinition(layer_id="backend", endpoint_patterns=["/api/*"]),
        ],
    )
    layer = policy.get_layer_for_endpoint("/api/users")
    assert layer is not None
    assert layer.layer_id == "backend"


class TestPolicyHashReproducibility:
    """Regression: policy_hash must be a pure function of policy CONTENT.

    The hash must NOT fold in wall-clock provenance (``generated_at``), so
    two fresh instances built from the same logical input produce an
    IDENTICAL ``policy_hash`` across runs. The wall-clock field is still
    recorded as metadata; it is only excluded from the hashed input.
    """

    @staticmethod
    def _build() -> ArchitecturePolicy:
        return ArchitecturePolicy(
            policy_id="repro-policy",
            policy_version="1.0.0",
            description="reproducibility regression",
            trust_zones=[
                TrustZone(zone_id="public", endpoint_patterns=["/public/*"]),
                TrustZone(zone_id="internal", endpoint_patterns=["/api/*"]),
            ],
            trust_boundary_rules=[
                TrustBoundaryRule(
                    rule_id="no-pub-to-int",
                    from_zone="public",
                    to_zone="internal",
                    action="FORBIDDEN",
                )
            ],
            layers=[LayerDefinition(layer_id="backend", endpoint_patterns=["/api/*"])],
            mutation_rules=[
                MutationRule(
                    rule_id="api-mut",
                    endpoint_pattern="/api/*",
                    methods=["POST"],
                    allowed_mutation_classes=["STATEFUL_MUTATION"],
                )
            ],
        )

    def test_policy_hash_is_reproducible(self):
        import time

        # Two fresh instances built from the same logical input, with a
        # wall-clock gap between construction so generated_at differs.
        p1 = self._build()
        time.sleep(0.01)
        p2 = self._build()

        # Wall-clock provenance actually diverged...
        assert p1.generated_at != p2.generated_at
        # ...but the content-addressed hash is identical.
        assert p1.compute_hash() == p2.compute_hash()

    def test_policy_generated_at_still_recorded(self):
        p = self._build()
        # The timestamp metadata is still present on the model.
        assert p.generated_at
        assert isinstance(p.generated_at, str)

    def test_policy_hash_changes_with_content(self):
        # Sanity: the hash is still sensitive to real content changes.
        p1 = self._build()
        p2 = self._build()
        p2.policy_id = "different-policy"
        assert p1.compute_hash() != p2.compute_hash()
