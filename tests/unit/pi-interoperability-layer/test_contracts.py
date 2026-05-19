"""Tests for canonical artifact contracts."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from pi_interoperability_layer.contracts import (
    ArtifactContract,
    ArtifactFingerprint,
    ContractRegistry,
    SchemaEvolutionLog,
    SchemaEvolutionRecord,
    SchemaVersion,
    canonical_json,
    compute_fingerprint,
)


class _TestPayload(BaseModel):
    field_a: str
    field_b: int
    model_config = {"frozen": True}


def test_schema_version_str() -> None:
    v = SchemaVersion(major=1, minor=2, patch=3)
    assert str(v) == "1.2.3"


def test_schema_version_with_label() -> None:
    v = SchemaVersion(major=1, minor=0, patch=0, label="beta")
    assert str(v) == "1.0.0-beta"


def test_schema_version_parse() -> None:
    v = SchemaVersion.parse("2.1.4-rc1")
    assert v.major == 2
    assert v.minor == 1
    assert v.patch == 4
    assert v.label == "rc1"


def test_schema_version_parse_invalid() -> None:
    with pytest.raises(ValueError):
        SchemaVersion.parse("1.2")


def test_contract_registry_register_and_get() -> None:
    registry = ContractRegistry(registry_id="test")
    contract = ArtifactContract(
        contract_id="c1",
        artifact_type="SemanticIRTrace",
        schema_version=SchemaVersion(major=1, minor=0, patch=0),
        schema_ref="SemanticIRTrace_v1",
    )
    registry.register(contract)
    assert registry.get("c1") is not None
    assert registry.registry_hash != ""


def test_contract_registry_compatible_exact() -> None:
    registry = ContractRegistry(registry_id="test")
    contract = ArtifactContract(
        contract_id="c1",
        artifact_type="SemanticIRTrace",
        schema_version=SchemaVersion(major=1, minor=0, patch=0),
        schema_ref="SemanticIRTrace_v1",
    )
    registry.register(contract)
    ok, reason = registry.compatible("c1", SchemaVersion(major=1, minor=0, patch=0))
    assert ok is True
    assert reason == "exact match"


def test_contract_registry_compatible_minor_bump() -> None:
    registry = ContractRegistry(registry_id="test")
    contract = ArtifactContract(
        contract_id="c1",
        artifact_type="SemanticIRTrace",
        schema_version=SchemaVersion(major=1, minor=0, patch=0),
        schema_ref="SemanticIRTrace_v1",
    )
    registry.register(contract)
    ok, reason = registry.compatible("c1", SchemaVersion(major=1, minor=1, patch=0))
    assert ok is True
    assert "backward compatible" in reason


def test_contract_registry_compatible_major_mismatch() -> None:
    registry = ContractRegistry(registry_id="test")
    contract = ArtifactContract(
        contract_id="c1",
        artifact_type="SemanticIRTrace",
        schema_version=SchemaVersion(major=1, minor=0, patch=0),
        schema_ref="SemanticIRTrace_v1",
    )
    registry.register(contract)
    ok, reason = registry.compatible("c1", SchemaVersion(major=2, minor=0, patch=0))
    assert ok is False
    assert "major version mismatch" in reason


def test_canonical_json_determinism() -> None:
    a = {"b": 1, "a": 2}
    b = {"a": 2, "b": 1}
    assert canonical_json(a) == canonical_json(b)


def test_compute_fingerprint() -> None:
    payload = _TestPayload(field_a="x", field_b=42)
    contract = ArtifactContract(
        contract_id="c1",
        artifact_type="SemanticIRTrace",
        schema_version=SchemaVersion(major=1, minor=0, patch=0),
        schema_ref="ref",
        fingerprint_fields=["field_a"],
    )
    fp = compute_fingerprint(payload, contract, generated_by="test")
    assert fp.artifact_type == "SemanticIRTrace"
    assert fp.schema_version == "1.0.0"
    assert fp.content_hash != ""
    assert fp.contract_hash != ""


def test_schema_evolution_log_append_and_hash() -> None:
    log = SchemaEvolutionLog(log_id="ev1")
    record = SchemaEvolutionRecord(
        record_id="r1",
        contract_id="c1",
        from_version="1.0.0",
        to_version="1.1.0",
        change_type="ADD_FIELD",
        description="Added field_c",
        backward_compatible=True,
        migration_required=False,
        replay_safe=True,
    )
    log.append(record)
    assert len(log.records) == 1
    assert log.log_hash != ""
