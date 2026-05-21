"""Canonical Artifact Contracts for pi-semantic runtimes.

Deterministic, versioned, fingerprinted artifact schemas.
No inference. No LLM calls. No probabilistic scoring.

Every artifact contract is:
  * frozen at a schema version
  * deterministically serializable
  * fingerprinted with SHA-256
  * append-only in evolution
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, Field

# ──────────────────────────────
#  Schema Version Primitive
# ──────────────────────────────

class SchemaVersion(BaseModel):
    """Semantic version for artifact contracts."""

    major: int = Field(..., ge=0)
    minor: int = Field(..., ge=0)
    patch: int = Field(..., ge=0)
    label: str = ""  # e.g. "beta", "rc1"

    model_config = {"frozen": True}

    def __str__(self) -> str:
        v = f"{self.major}.{self.minor}.{self.patch}"
        if self.label:
            v += f"-{self.label}"
        return v

    @classmethod
    def parse(cls, s: str) -> "SchemaVersion":
        parts = s.split("-", 1)
        label = parts[1] if len(parts) > 1 else ""
        nums = parts[0].split(".")
        if len(nums) != 3:
            raise ValueError(f"Invalid schema version: {s}")
        return cls(major=int(nums[0]), minor=int(nums[1]), patch=int(nums[2]), label=label)


# ──────────────────────────────
#  Artifact Contract Registry
# ──────────────────────────────

class ArtifactContract(BaseModel):
    """A frozen artifact contract definition."""

    contract_id: str
    artifact_type: Literal[
        "SemanticIRTrace",
        "DependencyGraph",
        "SynthesizedSpec",
        "SemanticDiff",
        "AuthInvariant",
        "ProtocolStateMachine",
        "ValidationReport",
        "GovernanceViolation",
        "BehavioralDelta",
        "ReplayLedger",
        "EventRecord",
    ]
    schema_version: SchemaVersion
    # Canonical JSON Schema (or Pydantic model name) for this contract
    schema_ref: str
    # Deterministic serialization rules
    serialization_rules: List[str] = Field(default_factory=list)
    # Fingerprint fields that MUST be included in artifact hash
    fingerprint_fields: List[str] = Field(default_factory=list)
    # Backward compatibility statement
    backward_compatible_with: List[str] = Field(default_factory=list)
    frozen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"frozen": True}


class ContractRegistry(BaseModel):
    """Centralized versioned schema authority for all runtime artifacts."""

    registry_id: str
    contracts: Dict[str, ArtifactContract] = Field(default_factory=dict)
    # Hash of the entire registry for determinism verification
    registry_hash: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def register(self, contract: ArtifactContract) -> None:
        self.contracts[contract.contract_id] = contract
        self._rehash()

    def _rehash(self) -> None:
        payload = json.dumps(
            {k: v.model_dump() for k, v in sorted(self.contracts.items())},
            sort_keys=True,
            default=str,
        )
        self.registry_hash = hashlib.sha256(payload.encode()).hexdigest()

    def get(self, contract_id: str) -> Optional[ArtifactContract]:
        return self.contracts.get(contract_id)

    def compatible(
        self,
        contract_id: str,
        candidate_version: SchemaVersion,
    ) -> Tuple[bool, str]:
        """Check if candidate_version is compatible with registered contract."""
        contract = self.contracts.get(contract_id)
        if not contract:
            return False, f"Contract {contract_id} not found"
        registered = contract.schema_version
        # Exact match always compatible
        if candidate_version == registered:
            return True, "exact match"
        # Same major means backward compatible (minor/patch can increase)
        if candidate_version.major == registered.major:
            if candidate_version.minor >= registered.minor:
                return True, "backward compatible (same major)"
            return False, "minor version regression"
        return False, "major version mismatch"


# ──────────────────────────────
#  Deterministic Fingerprinting
# ──────────────────────────────

class ArtifactFingerprint(BaseModel):
    """Deterministic fingerprint of an artifact instance."""

    artifact_type: str
    schema_version: str
    # SHA-256 of canonical serialized payload
    content_hash: str
    # Hash of the contract definition used
    contract_hash: str
    # Ordered list of provenance hashes
    provenance_hash_chain: List[str] = Field(default_factory=list)
    # Runtime that produced this artifact
    generated_by: str = ""
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"frozen": True}


def canonical_json(value: Any) -> str:
    """Deterministic JSON serialization: sorted keys, no whitespace variance."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def compute_fingerprint(
    artifact: BaseModel,
    contract: ArtifactContract,
    provenance: Optional[List[str]] = None,
    generated_by: str = "",
) -> ArtifactFingerprint:
    """Compute deterministic fingerprint for an artifact instance."""
    # Extract only fingerprint fields if defined; otherwise use full model
    if contract.fingerprint_fields:
        payload = {k: v for k, v in artifact.model_dump().items() if k in contract.fingerprint_fields}
    else:
        payload = artifact.model_dump()
    content_hash = hashlib.sha256(canonical_json(payload).encode()).hexdigest()
    contract_hash = hashlib.sha256(contract.model_dump_json().encode()).hexdigest()
    return ArtifactFingerprint(
        artifact_type=contract.artifact_type,
        schema_version=str(contract.schema_version),
        content_hash=content_hash,
        contract_hash=contract_hash,
        provenance_hash_chain=provenance or [],
        generated_by=generated_by,
    )


# ──────────────────────────────
#  Append-Only Compatibility Evolution
# ──────────────────────────────

class SchemaEvolutionRecord(BaseModel):
    """Immutable record of a schema evolution event."""

    record_id: str
    contract_id: str
    from_version: str
    to_version: str
    change_type: Literal["ADD_FIELD", "REMOVE_FIELD", "TYPE_CHANGE", "RULE_CHANGE", "DEPRECATE"]
    description: str
    backward_compatible: bool
    migration_required: bool
    replay_safe: bool
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    model_config = {"frozen": True}


class SchemaEvolutionLog(BaseModel):
    """Append-only log of all schema changes across the platform."""

    log_id: str
    records: List[SchemaEvolutionRecord] = Field(default_factory=list)
    log_hash: str = ""

    def append(self, record: SchemaEvolutionRecord) -> None:
        self.records.append(record)
        self._rehash()

    def _rehash(self) -> None:
        payload = canonical_json([r.model_dump() for r in self.records])
        self.log_hash = hashlib.sha256(payload.encode()).hexdigest()

    def changes_for_contract(self, contract_id: str) -> List[SchemaEvolutionRecord]:
        return [r for r in self.records if r.contract_id == contract_id]
