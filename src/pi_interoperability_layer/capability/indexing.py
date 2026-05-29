"""Semantic Indexing and Query Workers.

Deterministic semantic indexing for artifact retrieval.
Provenance-linked, append-only, no autonomous learning loops.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


class IndexField(Enum):
    ARTIFACT_TYPE = "artifact_type"
    ENDPOINT_PATH = "endpoint_path"
    NODE_ID = "node_id"
    CAPABILITY = "capability"
    STATUS = "status"
    TRUST_ZONE = "trust_zone"


@dataclass(frozen=True)
class IndexEntry:
    artifact_id: str
    artifact_type: str
    source_extension_id: str
    index_fields: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)
    provenance_hash: str = ""
    indexed_at: str = ""
    entry_hash: str = ""

    def compute_hash(self) -> str:
        payload = (
            f"{self.artifact_id}:{self.artifact_type}:"
            f"{self.source_extension_id}:"
            f"{json.dumps(dict(self.index_fields), sort_keys=True)}:"
            f"{self.provenance_hash}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()


class SemanticIndexWorker:
    """Deterministic indexer. No inference. No mutation."""

    def __init__(self, root_dir: Optional[Path] = None) -> None:
        self.root_dir = root_dir or Path.home() / ".pi_semantic_index"
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._entries: Dict[str, IndexEntry] = {}
        self._inverted: Dict[str, Set[str]] = {}  # field_value -> artifact_ids
        self._audit: List[str] = []

    def index(
        self,
        artifact_id: str,
        artifact_type: str,
        source_extension_id: str,
        fields: Dict[str, str],
        provenance_hash: str,
    ) -> IndexEntry:
        entry = IndexEntry(
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            source_extension_id=source_extension_id,
            index_fields=tuple(sorted(fields.items())),
            provenance_hash=provenance_hash,
            indexed_at=datetime.utcnow().isoformat() + "Z",
        )
        object.__setattr__(entry, "entry_hash", entry.compute_hash())
        self._entries[artifact_id] = entry
        for k, v in fields.items():
            key = f"{k}:{v}"
            self._inverted.setdefault(key, set()).add(artifact_id)
        self._audit.append(f"INDEX {artifact_id} {source_extension_id}")
        self._save(entry)
        return entry

    def query(
        self,
        artifact_type: Optional[str] = None,
        fields: Optional[Dict[str, str]] = None,
        source_extension_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[IndexEntry]:
        candidates: Optional[Set[str]] = None
        if fields:
            for k, v in fields.items():
                key = f"{k}:{v}"
                ids = self._inverted.get(key, set())
                if candidates is None:
                    candidates = set(ids)
                else:
                    candidates &= ids
        if candidates is None:
            candidates = set(self._entries.keys())
        results: List[IndexEntry] = []
        for eid in candidates:
            e = self._entries[eid]
            if artifact_type and e.artifact_type != artifact_type:
                continue
            if source_extension_id and e.source_extension_id != source_extension_id:
                continue
            results.append(e)
            if len(results) >= limit:
                break
        return results

    def query_by_provenance(self, provenance_hash: str) -> List[IndexEntry]:
        return [e for e in self._entries.values() if e.provenance_hash == provenance_hash]

    def lookup(self, artifact_id: str) -> Optional[IndexEntry]:
        return self._entries.get(artifact_id)

    def audit_log(self) -> List[str]:
        return list(self._audit)

    def _save(self, entry: IndexEntry) -> None:
        path = self.root_dir / f"{entry.artifact_id}.json"
        data = {
            "artifact_id": entry.artifact_id,
            "artifact_type": entry.artifact_type,
            "source_extension_id": entry.source_extension_id,
            "index_fields": dict(entry.index_fields),
            "provenance_hash": entry.provenance_hash,
            "indexed_at": entry.indexed_at,
            "entry_hash": entry.entry_hash,
        }
        path.write_text(json.dumps(data, indent=2, sort_keys=True))


class SemanticQueryWorker:
    """Deterministic query engine. No inference. Read-only."""

    def __init__(self, index: SemanticIndexWorker) -> None:
        self.index = index

    def get_by_id(self, artifact_id: str) -> Optional[IndexEntry]:
        return self.index.lookup(artifact_id)

    def get_by_type(self, artifact_type: str, limit: int = 100) -> List[IndexEntry]:
        return self.index.query(artifact_type=artifact_type, limit=limit)

    def get_by_source(self, extension_id: str) -> List[IndexEntry]:
        return self.index.query(source_extension_id=extension_id)

    def get_by_fields(self, fields: Dict[str, str]) -> List[IndexEntry]:
        return self.index.query(fields=fields)

    def lineage(self, artifact_id: str) -> List[IndexEntry]:
        """Return all artifacts from the same source extension."""
        entry = self.index._entries.get(artifact_id)
        if not entry:
            return []
        return self.index.query(source_extension_id=entry.source_extension_id)

    def cross_reference(
        self,
        artifact_type_a: str,
        artifact_type_b: str,
        join_field: str,
    ) -> List[Tuple[IndexEntry, IndexEntry]]:
        """Join two artifact types by a shared field value."""
        a_entries = self.index.query(artifact_type=artifact_type_a)
        b_entries = self.index.query(artifact_type=artifact_type_b)
        a_map: Dict[str, List[IndexEntry]] = {}
        for e in a_entries:
            for k, v in e.index_fields:
                if k == join_field:
                    a_map.setdefault(v, []).append(e)
        results: List[Tuple[IndexEntry, IndexEntry]] = []
        for e in b_entries:
            for k, v in e.index_fields:
                if k == join_field and v in a_map:
                    for ae in a_map[v]:
                        results.append((ae, e))
        return results
