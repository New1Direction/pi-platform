"""Semantic Artifact Registry.

Durable semantic memory layer. No agents. No inference.
Each artifact carries epistemic state, provenance, and trust metadata.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, List, Optional

from pydantic import BaseModel, Field

from pi_agent_chain.models import (
    EpistemicState,
)


class SemanticArtifact(BaseModel):
    """A durable knowledge artifact with full provenance and epistemic state."""

    artifact_id: str
    artifact_type: str  # "SemanticIRTrace" | "DependencyGraph" | "SynthesizedSpec"
    epistemic_state: str = Field(default=EpistemicState.OBSERVED)
    trust_score: float = Field(default=0.0, ge=0.0, le=1.0)
    provenance: List[str] = Field(default_factory=list)
    semantic_hash: str
    generated_by: str
    verification_status: str = "UNVERIFIED"
    payload_json: str  # serialized artifact
    captured_at: str = Field(default_factory=lambda: __import__("datetime").datetime.utcnow().isoformat())

    # Rich immutable provenance (Phase 1)
    parent_artifact_ids: List[str] = Field(default_factory=list)
    source_execution_id: str = ""
    originating_runtime_state: str = ""
    input_hash: str = ""
    output_hash: str = ""
    trace_hash: str = ""
    evidence_refs: List[str] = Field(default_factory=list)
    schema_version: str = "1.0.0"


class ArtifactRegistry:
    """SQLite-backed append-only registry for semantic artifacts.

    Artifacts NEVER mutate. State changes create new entries.
    This preserves epistemic traceability.
    """

    def __init__(self, db_path: Path | str = ":memory:") -> None:
        self.db_path = str(db_path)
        # Keep a persistent connection for :memory: so the schema survives across operations
        self._conn: Optional[sqlite3.Connection] = (
            sqlite3.connect(self.db_path) if self.db_path == ":memory:" else None
        )
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        conn = self._conn or sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT,
                    artifact_type TEXT,
                    epistemic_state TEXT,
                    trust_score REAL,
                    provenance TEXT,
                    semantic_hash TEXT,
                    generated_by TEXT,
                    verification_status TEXT,
                    payload_json TEXT,
                    captured_at TEXT,
                    parent_artifact_ids TEXT,
                    source_execution_id TEXT,
                    originating_runtime_state TEXT,
                    input_hash TEXT,
                    output_hash TEXT,
                    trace_hash TEXT,
                    evidence_refs TEXT,
                    schema_version TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_hash ON artifacts(semantic_hash)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_state ON artifacts(epistemic_state)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_parent ON artifacts(parent_artifact_ids)"
            )
            conn.commit()
        finally:
            if self._conn is None:
                conn.close()

    def store(self, artifact: SemanticArtifact) -> None:
        """Store a semantic artifact immutably."""
        conn = self._conn or sqlite3.connect(self.db_path)
        try:
            conn.execute(
                """
                INSERT INTO artifacts
                (artifact_id, artifact_type, epistemic_state, trust_score, provenance,
                 semantic_hash, generated_by, verification_status, payload_json, captured_at,
                 parent_artifact_ids, source_execution_id, originating_runtime_state,
                 input_hash, output_hash, trace_hash, evidence_refs, schema_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    artifact.artifact_id,
                    artifact.artifact_type,
                    artifact.epistemic_state,
                    artifact.trust_score,
                    json.dumps(artifact.provenance, sort_keys=True),
                    artifact.semantic_hash,
                    artifact.generated_by,
                    artifact.verification_status,
                    artifact.payload_json,
                    artifact.captured_at,
                    json.dumps(artifact.parent_artifact_ids, sort_keys=True),
                    artifact.source_execution_id,
                    artifact.originating_runtime_state,
                    artifact.input_hash,
                    artifact.output_hash,
                    artifact.trace_hash,
                    json.dumps(artifact.evidence_refs, sort_keys=True),
                    artifact.schema_version,
                ),
            )
            conn.commit()
        finally:
            if self._conn is None:
                conn.close()

    def find_by_hash(self, semantic_hash: str) -> Optional[SemanticArtifact]:
        conn = self._conn or sqlite3.connect(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM artifacts WHERE semantic_hash = ? ORDER BY captured_at DESC LIMIT 1",
                (semantic_hash,),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_artifact(row)
        finally:
            if self._conn is None:
                conn.close()

    def find_by_state(self, state: str) -> List[SemanticArtifact]:
        conn = self._conn or sqlite3.connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM artifacts WHERE epistemic_state = ? ORDER BY captured_at DESC",
                (state,),
            ).fetchall()
            return [self._row_to_artifact(r) for r in rows]
        finally:
            if self._conn is None:
                conn.close()

    def all_artifacts(self) -> List[SemanticArtifact]:
        conn = self._conn or sqlite3.connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM artifacts ORDER BY captured_at DESC"
            ).fetchall()
            return [self._row_to_artifact(r) for r in rows]
        finally:
            if self._conn is None:
                conn.close()

    @staticmethod
    def _row_to_artifact(row: sqlite3.Row) -> SemanticArtifact:
        return SemanticArtifact(
            artifact_id=row[0],
            artifact_type=row[1],
            epistemic_state=row[2],
            trust_score=row[3],
            provenance=json.loads(row[4]),
            semantic_hash=row[5],
            generated_by=row[6],
            verification_status=row[7],
            payload_json=row[8],
            captured_at=row[9],
            parent_artifact_ids=json.loads(row[10]) if row[10] else [],
            source_execution_id=row[11] if row[11] else "",
            originating_runtime_state=row[12] if row[12] else "",
            input_hash=row[13] if row[13] else "",
            output_hash=row[14] if row[14] else "",
            trace_hash=row[15] if row[15] else "",
            evidence_refs=json.loads(row[16]) if row[16] else [],
            schema_version=row[17] if row[17] else "1.0.0",
        )

    def promote(
        self, artifact: SemanticArtifact, new_state: str, trust_delta: float = 0.1
    ) -> SemanticArtifact:
        """Create a new artifact entry with updated epistemic state.

        Preserves immutability — the original artifact remains untouched.
        """
        new_trust = min(1.0, artifact.trust_score + trust_delta)
        promoted = SemanticArtifact(
            artifact_id=artifact.artifact_id,
            artifact_type=artifact.artifact_type,
            epistemic_state=new_state,
            trust_score=new_trust,
            provenance=artifact.provenance + [f"promoted:{new_state}"],
            semantic_hash=artifact.semantic_hash,
            generated_by=artifact.generated_by,
            verification_status=artifact.verification_status,
            payload_json=artifact.payload_json,
            captured_at=artifact.captured_at,
            parent_artifact_ids=artifact.parent_artifact_ids,
            source_execution_id=artifact.source_execution_id,
            originating_runtime_state=artifact.originating_runtime_state,
            input_hash=artifact.input_hash,
            output_hash=artifact.output_hash,
            trace_hash=artifact.trace_hash,
            evidence_refs=artifact.evidence_refs + [f"promotion_evidence:{new_state}"],
            schema_version=artifact.schema_version,
        )
        self.store(promoted)
        return promoted

    @staticmethod
    def derive_artifact(
        obj: Any,
        artifact_type: str,
        generated_by: str,
        provenance: Optional[List[str]] = None,
        parent_artifact_ids: Optional[List[str]] = None,
        source_execution_id: str = "",
        originating_runtime_state: str = "",
        input_hash: str = "",
        output_hash: str = "",
        trace_hash: str = "",
        evidence_refs: Optional[List[str]] = None,
        schema_version: str = "1.0.0",
    ) -> SemanticArtifact:
        """Factory: wrap any Pydantic object into a SemanticArtifact with full provenance."""
        payload = json.dumps(obj.model_dump(), sort_keys=True, default=str)
        sem_hash = hashlib.sha256(payload.encode()).hexdigest()
        return SemanticArtifact(
            artifact_id=hashlib.sha256(
                (sem_hash + generated_by).encode()
            ).hexdigest()[:16],
            artifact_type=artifact_type,
            epistemic_state=getattr(obj, "epistemic_state", EpistemicState.OBSERVED),
            trust_score=getattr(obj, "trust_score", 0.0),
            provenance=provenance or [],
            semantic_hash=sem_hash,
            generated_by=generated_by,
            verification_status=getattr(obj, "verification_status", "UNVERIFIED"),
            payload_json=payload,
            parent_artifact_ids=parent_artifact_ids or [],
            source_execution_id=source_execution_id,
            originating_runtime_state=originating_runtime_state,
            input_hash=input_hash,
            output_hash=output_hash,
            trace_hash=trace_hash,
            evidence_refs=evidence_refs or [],
            schema_version=schema_version,
        )
