"""Schema Registry for versioned artifact contracts.

Deterministic schema authority with compatibility validation.
No inference. No self-modification. No probabilistic scoring.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Tuple

from pydantic import BaseModel

from pi_interoperability_layer.contracts import (
    ArtifactContract,
    ContractRegistry,
    SchemaEvolutionLog,
    SchemaVersion,
)

# ──────────────────────────────
#  Compatibility Validation
# ──────────────────────────────


class CompatibilityResult(BaseModel):
    """Deterministic compatibility check outcome."""

    compatible: bool
    reason: str
    contract_id: str
    registered_version: str
    candidate_version: str
    replay_safe: bool
    model_config = {"frozen": True}


class SchemaValidator(BaseModel):
    """Deterministic schema compatibility validator."""

    registry: ContractRegistry
    evolution_log: SchemaEvolutionLog
    model_config = {"frozen": True}

    def validate_compatibility(
        self,
        contract_id: str,
        candidate_version: SchemaVersion,
    ) -> CompatibilityResult:
        """Check if a candidate artifact version is compatible with the registry."""
        contract = self.registry.get(contract_id)
        if not contract:
            return CompatibilityResult(
                compatible=False,
                reason=f"Contract {contract_id} not registered",
                contract_id=contract_id,
                registered_version="",
                candidate_version=str(candidate_version),
                replay_safe=False,
            )

        ok, reason = self.registry.compatible(contract_id, candidate_version)
        # Check evolution log for replay-safe migration path
        changes = self.evolution_log.changes_for_contract(contract_id)
        replay_safe = all(r.replay_safe for r in changes)

        return CompatibilityResult(
            compatible=ok,
            reason=reason,
            contract_id=contract_id,
            registered_version=str(contract.schema_version),
            candidate_version=str(candidate_version),
            replay_safe=replay_safe,
        )

    def validate_migration_path(
        self,
        contract_id: str,
        from_version: SchemaVersion,
        to_version: SchemaVersion,
    ) -> Tuple[bool, str]:
        """Validate that a migration path exists and is replay-safe."""
        changes = self.evolution_log.changes_for_contract(contract_id)
        relevant = [r for r in changes if r.from_version == str(from_version) and r.to_version == str(to_version)]
        if not relevant:
            return False, "No registered migration path"
        if not all(r.replay_safe for r in relevant):
            return False, "Migration path contains replay-unsafe changes"
        if not all(r.backward_compatible for r in relevant):
            return False, "Migration path contains backward-incompatible changes"
        return True, "replay-safe migration path confirmed"


# ──────────────────────────────
#  Registry Persistence
# ──────────────────────────────

REGISTRY_FILENAME = "schema-registry.json"
EVOLUTION_FILENAME = "schema-evolution.json"


def save_registry(registry: ContractRegistry, path: Path) -> None:
    """Persist registry deterministically."""
    with open(path / REGISTRY_FILENAME, "w", encoding="utf-8") as f:
        json.dump(registry.model_dump(), f, indent=2, sort_keys=True, default=str)


def load_registry(path: Path) -> ContractRegistry:
    """Load registry from disk."""
    with open(path / REGISTRY_FILENAME, "r", encoding="utf-8") as f:
        data = json.load(f)
    return ContractRegistry(**data)


def save_evolution_log(log: SchemaEvolutionLog, path: Path) -> None:
    """Persist evolution log deterministically."""
    with open(path / EVOLUTION_FILENAME, "w", encoding="utf-8") as f:
        json.dump(log.model_dump(), f, indent=2, sort_keys=True, default=str)


def load_evolution_log(path: Path) -> SchemaEvolutionLog:
    """Load evolution log from disk."""
    with open(path / EVOLUTION_FILENAME, "r", encoding="utf-8") as f:
        data = json.load(f)
    return SchemaEvolutionLog(**data)


# ──────────────────────────────
#  Deterministic Schema Identity
# ──────────────────────────────


def schema_identity_hash(contract: ArtifactContract) -> str:
    """Compute deterministic identity hash for a contract definition."""
    payload = json.dumps(
        contract.model_dump(),
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()
