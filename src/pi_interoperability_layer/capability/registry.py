"""Semantic Capability Registry.

Tracks all extensions entering the mesh with deterministic fingerprints,
policy-evidence trust scoring (not probabilistic), and replay safety
classifications.

No mutable long-term memory. No autonomous learning loops.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple

from pi_extension_governor.manifest import (
    CapabilityClass,
    ExtensionManifest,
    TrustZone,
)


class RegistryEntryStatus(Enum):
    REGISTERED = "registered"
    VALIDATED = "validated"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


class TrustScoringBasis(Enum):
    POLICY_EVIDENCE = "policy_evidence"
    DETERMINISM_PROOF = "determinism_proof"
    REPLAY_VERIFICATION = "replay_verification"
    STATIC_ANALYSIS = "static_analysis"
    MANUAL_REVIEW = "manual_review"


@dataclass(frozen=True)
class RegistryFingerprints:
    """Deterministic fingerprints for an extension."""

    manifest_hash: str
    source_hash: str
    determinism_fingerprint: str
    policy_hash: str
    normalization_hash: str
    provenance_chain_hash: str

    def combined_hash(self) -> str:
        return hashlib.sha256(
            f"{self.manifest_hash}:{self.source_hash}:{self.determinism_fingerprint}:"
            f"{self.policy_hash}:{self.normalization_hash}:{self.provenance_chain_hash}".encode()
        ).hexdigest()


@dataclass(frozen=True)
class TrustScore:
    """Evidence-based trust score. Scores are bounded integers [0, 100].

    NOT probabilistic. Each score is derived from deterministic policy evidence.
    """

    policy_passed: int = 0
    determinism_verified: int = 0
    replay_safe: int = 0
    static_clean: int = 0
    manual_reviewed: int = 0
    basis: Tuple[TrustScoringBasis, ...] = field(default_factory=tuple)

    @property
    def composite_score(self) -> int:
        return min(
            100,
            self.policy_passed
            + self.determinism_verified
            + self.replay_safe
            + self.static_clean
            + self.manual_reviewed,
        )

    def with_evidence(self, basis: TrustScoringBasis, value: int) -> TrustScore:
        kw: Dict[str, Any] = {}
        if basis == TrustScoringBasis.POLICY_EVIDENCE:
            kw["policy_passed"] = min(100, self.policy_passed + value)
        elif basis == TrustScoringBasis.DETERMINISM_PROOF:
            kw["determinism_verified"] = min(100, self.determinism_verified + value)
        elif basis == TrustScoringBasis.REPLAY_VERIFICATION:
            kw["replay_safe"] = min(100, self.replay_safe + value)
        elif basis == TrustScoringBasis.STATIC_ANALYSIS:
            kw["static_clean"] = min(100, self.static_clean + value)
        elif basis == TrustScoringBasis.MANUAL_REVIEW:
            kw["manual_reviewed"] = min(100, self.manual_reviewed + value)
        new_basis = tuple(set(self.basis) | {basis})
        return TrustScore(**kw, basis=new_basis)


@dataclass(frozen=True)
class RegistryEntry:
    """Immutable record of an extension in the capability registry."""

    extension_id: str
    name: str
    version: str
    registered_at: str  # ISO 8601
    fingerprints: RegistryFingerprints
    trust_score: TrustScore
    status: RegistryEntryStatus = RegistryEntryStatus.REGISTERED
    capability_class: Optional[CapabilityClass] = None
    trust_zone: TrustZone = TrustZone.SANDBOX_EXPERIMENTAL
    manifest_snapshot: str = ""  # JSON snapshot of ExtensionManifest
    previous_entry_hash: str = ""
    entry_hash: str = ""

    def compute_hash(self) -> str:
        # Content-addressed identity hash. Excludes the wall-clock registered_at
        # (it would salt the hash per run, breaking reproducibility). Causal
        # position is captured by previous_entry_hash (chain link). registered_at
        # remains STORED on the entry as metadata.
        payload = (
            f"{self.extension_id}:{self.name}:{self.version}:"
            f"{self.fingerprints.combined_hash()}:"
            f"{self.trust_score.composite_score}:{self.status.value}:"
            f"{self.previous_entry_hash}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def __post_init__(self) -> None:
        # Since dataclass is NOT frozen for post_init, we can set entry_hash
        object.__setattr__(self, "entry_hash", self.compute_hash())


class RegistryIndexKey(NamedTuple):
    capability_class: Optional[CapabilityClass]
    trust_zone: TrustZone
    status: RegistryEntryStatus


class SemanticCapabilityRegistry:
    """Deterministic extension catalog. Append-only. No learning loops."""

    def __init__(self, root_dir: Optional[Path] = None):
        self.root_dir = root_dir or Path.home() / ".pi_semantic_registry"
        self.root_dir.mkdir(parents=True, exist_ok=True)

        self._entries: Dict[str, RegistryEntry] = {}  # extension_id -> entry
        self._index: Dict[RegistryIndexKey, Set[str]] = {}
        self._capability_graph: Dict[str, Set[str]] = {}  # ext_id -> requires ext_ids
        self._audit_log: List[str] = []

    def register(
        self,
        manifest: ExtensionManifest,
        fingerprints: RegistryFingerprints,
        trust_score: TrustScore,
        status: RegistryEntryStatus = RegistryEntryStatus.REGISTERED,
        previous_entry_hash: str = "",
    ) -> RegistryEntry:
        entry = RegistryEntry(
            extension_id=manifest.extension_id,
            name=manifest.package_name,
            version=manifest.package_version,
            registered_at=datetime.utcnow().isoformat() + "Z",
            fingerprints=fingerprints,
            trust_score=trust_score,
            status=status,
            capability_class=manifest.capability_class,
            trust_zone=manifest.trust_zone,
            manifest_snapshot=manifest.model_dump_json(),
            previous_entry_hash=previous_entry_hash,
        )
        self._entries[entry.extension_id] = entry
        key = RegistryIndexKey(entry.capability_class, entry.trust_zone, entry.status)
        self._index.setdefault(key, set()).add(entry.extension_id)
        self._audit_log.append(f"REGISTER {entry.extension_id} {entry.entry_hash}")
        self._save_entry(entry)
        return entry

    def update_status(
        self,
        extension_id: str,
        new_status: RegistryEntryStatus,
        trust_score: Optional[TrustScore] = None,
    ) -> RegistryEntry:
        old = self._entries.get(extension_id)
        if old is None:
            raise KeyError(f"Extension {extension_id} not registered")
        new_entry = RegistryEntry(
            extension_id=old.extension_id,
            name=old.name,
            version=old.version,
            registered_at=old.registered_at,
            fingerprints=old.fingerprints,
            trust_score=trust_score or old.trust_score,
            status=new_status,
            capability_class=old.capability_class,
            trust_zone=old.trust_zone,
            manifest_snapshot=old.manifest_snapshot,
            previous_entry_hash=old.entry_hash,
        )
        self._entries[extension_id] = new_entry
        old_key = RegistryIndexKey(old.capability_class, old.trust_zone, old.status)
        new_key = RegistryIndexKey(new_entry.capability_class, new_entry.trust_zone, new_entry.status)
        self._index[old_key].discard(extension_id)
        if not self._index[old_key]:
            del self._index[old_key]
        self._index.setdefault(new_key, set()).add(extension_id)
        self._audit_log.append(f"UPDATE {extension_id} {new_status.value} {new_entry.entry_hash}")
        self._save_entry(new_entry)
        return new_entry

    def lookup(self, extension_id: str) -> Optional[RegistryEntry]:
        return self._entries.get(extension_id)

    def lookup_by_fingerprint(self, fingerprint: str) -> Optional[RegistryEntry]:
        for entry in self._entries.values():
            if entry.fingerprints.combined_hash() == fingerprint:
                return entry
        return None

    def query(
        self,
        capability_class: Optional[CapabilityClass] = None,
        trust_zone: Optional[TrustZone] = None,
        status: Optional[RegistryEntryStatus] = None,
        min_trust_score: int = 0,
    ) -> List[RegistryEntry]:
        key = RegistryIndexKey(capability_class, trust_zone, status)

        # If any field is None, we need to scan instead of exact index match
        def _match(eid: str) -> bool:
            e = self._entries[eid]
            if capability_class is not None and e.capability_class != capability_class:
                return False
            if trust_zone is not None and e.trust_zone != trust_zone:
                return False
            if status is not None and e.status != status:
                return False
            return e.trust_score.composite_score >= min_trust_score

        if None not in (capability_class, trust_zone, status):
            candidates = list(self._index.get(key, set()))
        else:
            candidates = list(self._entries.keys())
        return sorted(
            [self._entries[eid] for eid in candidates if _match(eid)],
            key=lambda e: e.trust_score.composite_score,
            reverse=True,
        )

    def record_dependency(self, extension_id: str, requires: str) -> None:
        if extension_id not in self._entries:
            raise KeyError(f"Extension {extension_id} not registered")
        if requires not in self._entries:
            raise KeyError(f"Required extension {requires} not registered")
        self._capability_graph.setdefault(extension_id, set()).add(requires)
        self._audit_log.append(f"DEPENDS {extension_id} -> {requires}")

    def get_dependencies(self, extension_id: str) -> Set[str]:
        return set(self._capability_graph.get(extension_id, set()))

    def verify_chain_integrity(self) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        # Index resident entries by their content-addressed hash so we can
        # actually LINK previous_entry_hash references (not just self-check each
        # entry's recomputed hash).
        by_hash: Dict[str, RegistryEntry] = {e.entry_hash: e for e in self._entries.values()}
        for eid, entry in self._entries.items():
            # 1. Self-check: the stored content-addressed hash must recompute.
            if entry.entry_hash != entry.compute_hash():
                errors.append(f"Hash mismatch: {eid}")
            # 2. Chain link: a chained entry must not reference itself, and when
            #    its predecessor is still resident it must belong to the same
            #    extension lineage.
            prev = entry.previous_entry_hash
            if prev:
                if prev == entry.entry_hash:
                    errors.append(f"Self-referential chain link: {eid}")
                predecessor = by_hash.get(prev)
                if predecessor is not None and predecessor.extension_id != entry.extension_id:
                    errors.append(
                        f"Chain lineage mismatch: {eid} links to {predecessor.extension_id}"
                    )
        return len(errors) == 0, errors

    def audit_log(self) -> List[str]:
        return list(self._audit_log)

    def _save_entry(self, entry: RegistryEntry) -> None:
        path = self.root_dir / f"{entry.extension_id}.json"
        data: Dict[str, Any] = {
            "extension_id": entry.extension_id,
            "name": entry.name,
            "version": entry.version,
            "registered_at": entry.registered_at,
            "fingerprints": {
                "manifest_hash": entry.fingerprints.manifest_hash,
                "source_hash": entry.fingerprints.source_hash,
                "determinism_fingerprint": entry.fingerprints.determinism_fingerprint,
                "policy_hash": entry.fingerprints.policy_hash,
                "normalization_hash": entry.fingerprints.normalization_hash,
                "provenance_chain_hash": entry.fingerprints.provenance_chain_hash,
                "combined_hash": entry.fingerprints.combined_hash(),
            },
            "trust_score": {
                "policy_passed": entry.trust_score.policy_passed,
                "determinism_verified": entry.trust_score.determinism_verified,
                "replay_safe": entry.trust_score.replay_safe,
                "static_clean": entry.trust_score.static_clean,
                "manual_reviewed": entry.trust_score.manual_reviewed,
                "basis": [b.value for b in entry.trust_score.basis],
                "composite_score": entry.trust_score.composite_score,
            },
            "status": entry.status.value,
            "capability_class": entry.capability_class.value if entry.capability_class else None,
            "trust_zone": entry.trust_zone.value,
            "manifest_snapshot": entry.manifest_snapshot,
            "previous_entry_hash": entry.previous_entry_hash,
            "entry_hash": entry.entry_hash,
        }
        path.write_text(json.dumps(data, indent=2, sort_keys=True))
