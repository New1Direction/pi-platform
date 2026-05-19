"""Tests for schema registry and compatibility validation."""

from __future__ import annotations

import pytest

from pi_interoperability_layer.contracts import (
    ArtifactContract,
    ContractRegistry,
    SchemaEvolutionLog,
    SchemaEvolutionRecord,
    SchemaVersion,
)
from pi_interoperability_layer.schema_registry import (
    SchemaValidator,
    schema_identity_hash,
)


def test_schema_validator_exact_match() -> None:
    registry = ContractRegistry(registry_id="reg1")
    registry.register(
        ArtifactContract(
            contract_id="c1",
            artifact_type="SemanticIRTrace",
            schema_version=SchemaVersion(major=1, minor=0, patch=0),
            schema_ref="ref",
        )
    )
    log = SchemaEvolutionLog(log_id="ev1")
    validator = SchemaValidator(registry=registry, evolution_log=log)
    result = validator.validate_compatibility("c1", SchemaVersion(major=1, minor=0, patch=0))
    assert result.compatible is True
    assert result.reason == "exact match"


def test_schema_validator_minor_bump() -> None:
    registry = ContractRegistry(registry_id="reg1")
    registry.register(
        ArtifactContract(
            contract_id="c1",
            artifact_type="SemanticIRTrace",
            schema_version=SchemaVersion(major=1, minor=0, patch=0),
            schema_ref="ref",
        )
    )
    log = SchemaEvolutionLog(log_id="ev1")
    log.append(
        SchemaEvolutionRecord(
            record_id="r1",
            contract_id="c1",
            from_version="1.0.0",
            to_version="1.1.0",
            change_type="ADD_FIELD",
            description="Add x",
            backward_compatible=True,
            migration_required=False,
            replay_safe=True,
        )
    )
    validator = SchemaValidator(registry=registry, evolution_log=log)
    result = validator.validate_compatibility("c1", SchemaVersion(major=1, minor=1, patch=0))
    assert result.compatible is True
    assert result.replay_safe is True


def test_schema_validator_major_mismatch() -> None:
    registry = ContractRegistry(registry_id="reg1")
    registry.register(
        ArtifactContract(
            contract_id="c1",
            artifact_type="SemanticIRTrace",
            schema_version=SchemaVersion(major=1, minor=0, patch=0),
            schema_ref="ref",
        )
    )
    log = SchemaEvolutionLog(log_id="ev1")
    validator = SchemaValidator(registry=registry, evolution_log=log)
    result = validator.validate_compatibility("c1", SchemaVersion(major=2, minor=0, patch=0))
    assert result.compatible is False
    assert "major version mismatch" in result.reason


def test_schema_validator_missing_contract() -> None:
    registry = ContractRegistry(registry_id="reg1")
    log = SchemaEvolutionLog(log_id="ev1")
    validator = SchemaValidator(registry=registry, evolution_log=log)
    result = validator.validate_compatibility("missing", SchemaVersion(major=1, minor=0, patch=0))
    assert result.compatible is False
    assert "not registered" in result.reason


def test_schema_validator_migration_path_ok() -> None:
    registry = ContractRegistry(registry_id="reg1")
    registry.register(
        ArtifactContract(
            contract_id="c1",
            artifact_type="SemanticIRTrace",
            schema_version=SchemaVersion(major=1, minor=0, patch=0),
            schema_ref="ref",
        )
    )
    log = SchemaEvolutionLog(log_id="ev1")
    log.append(
        SchemaEvolutionRecord(
            record_id="r1",
            contract_id="c1",
            from_version="1.0.0",
            to_version="1.1.0",
            change_type="ADD_FIELD",
            description="Add x",
            backward_compatible=True,
            migration_required=False,
            replay_safe=True,
        )
    )
    validator = SchemaValidator(registry=registry, evolution_log=log)
    ok, reason = validator.validate_migration_path(
        "c1", SchemaVersion(major=1, minor=0, patch=0), SchemaVersion(major=1, minor=1, patch=0)
    )
    assert ok is True
    assert "replay-safe migration path confirmed" in reason


def test_schema_validator_migration_path_unsafe() -> None:
    registry = ContractRegistry(registry_id="reg1")
    registry.register(
        ArtifactContract(
            contract_id="c1",
            artifact_type="SemanticIRTrace",
            schema_version=SchemaVersion(major=1, minor=0, patch=0),
            schema_ref="ref",
        )
    )
    log = SchemaEvolutionLog(log_id="ev1")
    log.append(
        SchemaEvolutionRecord(
            record_id="r1",
            contract_id="c1",
            from_version="1.0.0",
            to_version="1.1.0",
            change_type="TYPE_CHANGE",
            description="Change type",
            backward_compatible=True,
            migration_required=True,
            replay_safe=False,
        )
    )
    validator = SchemaValidator(registry=registry, evolution_log=log)
    ok, reason = validator.validate_migration_path(
        "c1", SchemaVersion(major=1, minor=0, patch=0), SchemaVersion(major=1, minor=1, patch=0)
    )
    assert ok is False
    assert "replay-unsafe changes" in reason


def test_schema_identity_hash_determinism() -> None:
    from datetime import datetime, timezone
    frozen = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    c1 = ArtifactContract(
        contract_id="c1",
        artifact_type="SemanticIRTrace",
        schema_version=SchemaVersion(major=1, minor=0, patch=0),
        schema_ref="ref",
        frozen_at=frozen,
    )
    c2 = ArtifactContract(
        contract_id="c1",
        artifact_type="SemanticIRTrace",
        schema_version=SchemaVersion(major=1, minor=0, patch=0),
        schema_ref="ref",
        frozen_at=frozen,
    )
    assert schema_identity_hash(c1) == schema_identity_hash(c2)
