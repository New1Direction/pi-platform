"""Runtime Schema Evolution.

Deterministic artifact schema versioning, compatibility validation,
and explicit migration registry.

Every schema is identified by SHA-256. Every migration is explicit,
versioned, and reversible. No automatic schema changes. No runtime
schema inference. All compatibility is statically validated before
deployment.

Key concepts:
- SchemaFingerprint: SHA-256 of canonical schema JSON
- CompatibilityLevel: NONE, BACKWARD, FORWARD, FULL
- MigrationStep: explicit transformation from one fingerprint to another
- MigrationDAG: directed graph of known migrations
- SchemaRegistry: append-only registry of schemas and migrations
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

# ──────────────────────────────
#  Compatibility Semantics
# ──────────────────────────────

class CompatibilityLevel(str, Enum):
    NONE = "none"
    BACKWARD = "backward"  # New readers can read old data
    FORWARD = "forward"    # Old readers can read new data
    FULL = "full"          # Both directions


class SchemaChangeType(str, Enum):
    FIELD_ADDED_OPTIONAL = "field_added_optional"
    FIELD_ADDED_REQUIRED = "field_added_required"
    FIELD_REMOVED = "field_removed"
    FIELD_TYPE_CHANGED = "field_type_changed"
    FIELD_DEFAULT_CHANGED = "field_default_changed"
    NESTED_SCHEMA_CHANGED = "nested_schema_changed"
    CONSTRAINT_CHANGED = "constraint_changed"
    ENUM_VARIANT_ADDED = "enum_variant_added"
    ENUM_VARIANT_REMOVED = "enum_variant_removed"


# ──────────────────────────────
#  Schema Model
# ──────────────────────────────

@dataclass(frozen=True)
class SchemaFingerprint:
    """Immutable SHA-256 identifier for a canonical schema representation."""

    algorithm: str = "sha256"
    value: str = ""
    schema_json: str = ""  # the canonical JSON that produced the hash

    def __post_init__(self, _: Any = None) -> None:
        if not self.value and self.schema_json:
            object.__setattr__(
                self,
                "value",
                hashlib.sha256(self.schema_json.encode()).hexdigest(),
            )

    def __str__(self) -> str:
        return f"{self.algorithm}:{self.value[:16]}..."

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SchemaFingerprint):
            return self.value == other.value
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.algorithm, self.value))


@dataclass(frozen=True)
class FieldSchema:
    """A single field in an artifact schema."""

    name: str
    type: str
    required: bool = True
    default: Any = None
    description: str = ""
    nested_schema_fingerprint: Optional[SchemaFingerprint] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "name": self.name,
            "type": self.type,
            "required": self.required,
            "default": self.default,
            "description": self.description,
        }
        if self.nested_schema_fingerprint:
            d["nested_schema_fingerprint"] = self.nested_schema_fingerprint.value
        return d


@dataclass(frozen=True)
class ArtifactSchema:
    """A versioned artifact schema with canonical representation."""

    schema_name: str
    version: str  # semantic version or build id
    fields: Tuple[FieldSchema, ...]
    compatibility: CompatibilityLevel
    previous_fingerprint: Optional[SchemaFingerprint] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    fingerprint: SchemaFingerprint = field(default_factory=lambda: SchemaFingerprint())

    def __post_init__(self, _: Any = None) -> None:
        if not self.fingerprint.value:
            canonical = self._canonical_json()
            fp = SchemaFingerprint(schema_json=canonical)
            object.__setattr__(self, "fingerprint", fp)
            object.__setattr__(self, "metadata", dict(self.metadata))
            object.__setattr__(self, "metadata", {**self.metadata, "canonical_json": canonical})

    def _canonical_json(self) -> str:
        canonical = {
            "schema_name": self.schema_name,
            "version": self.version,
            "fields": [f.to_dict() for f in sorted(self.fields, key=lambda f: f.name)],
            "compatibility": self.compatibility.value,
        }
        return json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str)

    def get_field(self, name: str) -> Optional[FieldSchema]:
        for f in self.fields:
            if f.name == name:
                return f
        return None


# ──────────────────────────────
#  Compatibility Validator
# ──────────────────────────────

@dataclass(frozen=True)
class CompatibilityReport:
    old_fingerprint: str
    new_fingerprint: str
    compatible: bool
    level: CompatibilityLevel
    changes: List[Dict[str, Any]]
    violations: List[str]


class CompatibilityValidator:
    """Deterministic compatibility checker between two artifact schemas.

    No heuristics. No probability. Explicit rules only.
    """

    RULES: Dict[CompatibilityLevel, Set[SchemaChangeType]] = {
        CompatibilityLevel.NONE: {
            SchemaChangeType.FIELD_ADDED_OPTIONAL,
            SchemaChangeType.FIELD_ADDED_REQUIRED,
            SchemaChangeType.FIELD_REMOVED,
            SchemaChangeType.FIELD_TYPE_CHANGED,
            SchemaChangeType.FIELD_DEFAULT_CHANGED,
            SchemaChangeType.NESTED_SCHEMA_CHANGED,
            SchemaChangeType.CONSTRAINT_CHANGED,
            SchemaChangeType.ENUM_VARIANT_ADDED,
            SchemaChangeType.ENUM_VARIANT_REMOVED,
        },
        CompatibilityLevel.BACKWARD: {
            SchemaChangeType.FIELD_ADDED_OPTIONAL,
            SchemaChangeType.FIELD_DEFAULT_CHANGED,
            SchemaChangeType.ENUM_VARIANT_ADDED,
            SchemaChangeType.NESTED_SCHEMA_CHANGED,
        },
        CompatibilityLevel.FORWARD: {
            SchemaChangeType.FIELD_REMOVED,
            SchemaChangeType.ENUM_VARIANT_REMOVED,
            SchemaChangeType.FIELD_DEFAULT_CHANGED,
            SchemaChangeType.NESTED_SCHEMA_CHANGED,
        },
        CompatibilityLevel.FULL: set(),  # No changes permitted without explicit migration
    }

    @classmethod
    def validate(cls, old: ArtifactSchema, new: ArtifactSchema) -> CompatibilityReport:
        changes = cls._diff(old, new)
        violations: List[str] = []
        allowed = cls.RULES.get(new.compatibility, set())

        for change in changes:
            if change["type"] not in allowed:
                violations.append(
                    f"{change['type']} not allowed under {new.compatibility.value} compatibility"
                )

        return CompatibilityReport(
            old_fingerprint=old.fingerprint.value,
            new_fingerprint=new.fingerprint.value,
            compatible=len(violations) == 0,
            level=new.compatibility,
            changes=changes,
            violations=violations,
        )

    @classmethod
    def _diff(cls, old: ArtifactSchema, new: ArtifactSchema) -> List[Dict[str, Any]]:
        changes: List[Dict[str, Any]] = []
        old_fields = {f.name: f for f in old.fields}
        new_fields = {f.name: f for f in new.fields}

        # Added fields
        for name, f in new_fields.items():
            if name not in old_fields:
                changes.append({
                    "type": SchemaChangeType.FIELD_ADDED_REQUIRED if f.required else SchemaChangeType.FIELD_ADDED_OPTIONAL,
                    "field": name,
                    "required": f.required,
                })

        # Removed fields
        for name in old_fields:
            if name not in new_fields:
                changes.append({
                    "type": SchemaChangeType.FIELD_REMOVED,
                    "field": name,
                })

        # Modified fields
        for name in old_fields:
            if name in new_fields:
                o = old_fields[name]
                n = new_fields[name]
                if o.type != n.type:
                    changes.append({"type": SchemaChangeType.FIELD_TYPE_CHANGED, "field": name})
                if o.default != n.default:
                    changes.append({"type": SchemaChangeType.FIELD_DEFAULT_CHANGED, "field": name})
                if o.nested_schema_fingerprint != n.nested_schema_fingerprint:
                    changes.append({"type": SchemaChangeType.NESTED_SCHEMA_CHANGED, "field": name})

        return changes


# ──────────────────────────────
#  Migration Model
# ──────────────────────────────

@dataclass(frozen=True)
class MigrationStep:
    """Explicit, reversible schema transformation."""

    migration_id: str
    from_fingerprint: str
    to_fingerprint: str
    direction: str  # "forward" | "backward"
    transformation_type: str  # "add_field", "remove_field", "rename_field", "change_type", "custom"
    field_name: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    deterministic: bool = True
    reversible: bool = False


class MigrationDAG:
    """Directed graph of known schema migrations.

    Migrations form explicit paths between schema versions.
    No automatic migration. Every path must be registered explicitly.
    """

    def __init__(self) -> None:
        self._forward: Dict[str, List[MigrationStep]] = {}  # from_fp -> steps
        self._backward: Dict[str, List[MigrationStep]] = {}  # to_fp -> steps
        self._lock = threading.Lock()

    def register(self, step: MigrationStep) -> None:
        with self._lock:
            if step.from_fingerprint not in self._forward:
                self._forward[step.from_fingerprint] = []
            self._forward[step.from_fingerprint].append(step)

            if step.to_fingerprint not in self._backward:
                self._backward[step.to_fingerprint] = []
            self._backward[step.to_fingerprint].append(step)

    def find_path(
        self,
        from_fp: str,
        to_fp: str,
        max_hops: int = 5,
    ) -> List[MigrationStep]:
        """Breadth-first search for a migration path.

        Returns the shortest path (fewest steps). No heuristics.
        """
        if from_fp == to_fp:
            return []

        visited: Set[str] = set()
        queue: List[Tuple[str, List[MigrationStep]]] = [(from_fp, [])]

        while queue:
            current_fp, path = queue.pop(0)
            if current_fp in visited:
                continue
            visited.add(current_fp)

            for step in self._forward.get(current_fp, []):
                new_path = path + [step]
                if step.to_fingerprint == to_fp:
                    return new_path
                if len(new_path) < max_hops:
                    queue.append((step.to_fingerprint, new_path))

        return []

    def has_path(self, from_fp: str, to_fp: str, max_hops: int = 5) -> bool:
        return len(self.find_path(from_fp, to_fp, max_hops)) > 0

    def get_migrations_from(self, fp: str) -> List[MigrationStep]:
        with self._lock:
            return list(self._forward.get(fp, []))


# ──────────────────────────────
#  Schema Registry
# ──────────────────────────────

class SchemaRegistry:
    """Append-only registry for schemas, compatibility reports, and migrations.

    No schema deletion. No migration removal. Historical record is immutable.
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS registered_schemas (
        schema_id INTEGER PRIMARY KEY AUTOINCREMENT,
        schema_name TEXT NOT NULL,
        version TEXT NOT NULL,
        fingerprint TEXT NOT NULL UNIQUE,
        canonical_json TEXT NOT NULL,
        compatibility TEXT NOT NULL,
        previous_fingerprint TEXT,
        registered_at TEXT NOT NULL,
        registered_by TEXT NOT NULL,
        UNIQUE(schema_name, version)
    );

    CREATE TABLE IF NOT EXISTS compatibility_reports (
        report_id INTEGER PRIMARY KEY AUTOINCREMENT,
        old_fingerprint TEXT NOT NULL,
        new_fingerprint TEXT NOT NULL,
        compatible INTEGER NOT NULL,
        level TEXT NOT NULL,
        changes_json TEXT NOT NULL,
        violations_json TEXT NOT NULL,
        validated_at TEXT NOT NULL,
        UNIQUE(old_fingerprint, new_fingerprint)
    );

    CREATE TABLE IF NOT EXISTS migration_registry (
        migration_id TEXT PRIMARY KEY,
        from_fingerprint TEXT NOT NULL,
        to_fingerprint TEXT NOT NULL,
        direction TEXT NOT NULL,
        transformation_type TEXT NOT NULL,
        field_name TEXT NOT NULL DEFAULT '',
        parameters_json TEXT NOT NULL DEFAULT '{}',
        description TEXT NOT NULL DEFAULT '',
        deterministic INTEGER NOT NULL DEFAULT 1,
        reversible INTEGER NOT NULL DEFAULT 0,
        registered_at TEXT NOT NULL,
        registered_by TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_migrations_from ON migration_registry(from_fingerprint);
    CREATE INDEX IF NOT EXISTS idx_migrations_to ON migration_registry(to_fingerprint);
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._dag = MigrationDAG()
        self._ensure_schema()
        self._load_migrations_into_dag()

    def _ensure_schema(self) -> None:
        with self._lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.executescript(self.SCHEMA)
            conn.commit()
            conn.close()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ── Schema Registration ─────────────────────────────────

    def register_schema(self, schema: ArtifactSchema, registered_by: str = "system") -> str:
        with self._lock:
            conn = self._conn()
            conn.execute(
                """INSERT OR IGNORE INTO registered_schemas
                   (schema_name, version, fingerprint, canonical_json, compatibility, previous_fingerprint, registered_at, registered_by)
                   VALUES (?, ?, ?, ?, ?, ?, datetime('now'), ?)""",
                (
                    schema.schema_name, schema.version, schema.fingerprint.value,
                    schema.fingerprint.schema_json, schema.compatibility.value,
                    schema.previous_fingerprint.value if schema.previous_fingerprint else None,
                    registered_by,
                ),
            )
            conn.commit()
            conn.close()
        return schema.fingerprint.value

    def get_schema(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                "SELECT * FROM registered_schemas WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()
            conn.close()
        return dict(row) if row else None

    def list_schema_versions(self, schema_name: str) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._conn()
            rows = conn.execute(
                "SELECT * FROM registered_schemas WHERE schema_name = ? ORDER BY version ASC",
                (schema_name,),
            ).fetchall()
            conn.close()
        return [dict(r) for r in rows]

    # ── Compatibility Validation ──────────────────────────────

    def validate_compatibility(
        self, old: ArtifactSchema, new: ArtifactSchema
    ) -> CompatibilityReport:
        report = CompatibilityValidator.validate(old, new)

        with self._lock:
            conn = self._conn()
            conn.execute(
                """INSERT OR IGNORE INTO compatibility_reports
                   (old_fingerprint, new_fingerprint, compatible, level, changes_json, violations_json, validated_at)
                   VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
                (
                    report.old_fingerprint, report.new_fingerprint,
                    1 if report.compatible else 0, report.level.value,
                    json.dumps(report.changes, sort_keys=True, default=str),
                    json.dumps(report.violations, sort_keys=True),
                ),
            )
            conn.commit()
            conn.close()

        return report

    def get_compatibility_report(self, old_fp: str, new_fp: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                "SELECT * FROM compatibility_reports WHERE old_fingerprint = ? AND new_fingerprint = ?",
                (old_fp, new_fp),
            ).fetchone()
            conn.close()
        return dict(row) if row else None

    # ── Migration Registry ───────────────────────────────────

    def register_migration(self, step: MigrationStep, registered_by: str = "system") -> None:
        with self._lock:
            conn = self._conn()
            conn.execute(
                """INSERT OR IGNORE INTO migration_registry
                   (migration_id, from_fingerprint, to_fingerprint, direction, transformation_type,
                    field_name, parameters_json, description, deterministic, reversible, registered_at, registered_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)""",
                (
                    step.migration_id, step.from_fingerprint, step.to_fingerprint,
                    step.direction, step.transformation_type, step.field_name,
                    json.dumps(step.parameters, sort_keys=True), step.description,
                    1 if step.deterministic else 0, 1 if step.reversible else 0,
                    registered_by,
                ),
            )
            conn.commit()
            conn.close()
        self._dag.register(step)

    def _load_migrations_into_dag(self) -> None:
        with self._lock:
            conn = self._conn()
            rows = conn.execute("SELECT * FROM migration_registry").fetchall()
            conn.close()
        for row in rows:
            step = MigrationStep(
                migration_id=row["migration_id"],
                from_fingerprint=row["from_fingerprint"],
                to_fingerprint=row["to_fingerprint"],
                direction=row["direction"],
                transformation_type=row["transformation_type"],
                field_name=row["field_name"],
                parameters=json.loads(row["parameters_json"]),
                description=row["description"],
                deterministic=bool(row["deterministic"]),
                reversible=bool(row["reversible"]),
            )
            self._dag.register(step)

    def find_migration_path(self, from_fp: str, to_fp: str, max_hops: int = 5) -> List[MigrationStep]:
        return self._dag.find_path(from_fp, to_fp, max_hops)

    def has_migration_path(self, from_fp: str, to_fp: str) -> bool:
        return self._dag.has_path(from_fp, to_fp)

    def get_migrations_from(self, fp: str) -> List[MigrationStep]:
        return self._dag.get_migrations_from(fp)

    # ── Migration Execution (Explicit, Reversible) ────────────────

    def apply_migration(
        self,
        data: Dict[str, Any],
        step: MigrationStep,
        direction: str = "forward",
    ) -> Dict[str, Any]:
        """Apply a single migration step to data.

        Deterministic, no probabilistic transforms.
        """
        result = dict(data)

        if step.transformation_type == "add_field":
            if direction == "forward":
                if step.field_name not in result:
                    result[step.field_name] = step.parameters.get("default")
            else:  # backward
                result.pop(step.field_name, None)

        elif step.transformation_type == "remove_field":
            if direction == "forward":
                result.pop(step.field_name, None)
            else:
                result[step.field_name] = step.parameters.get("restore_value")

        elif step.transformation_type == "rename_field":
            if direction == "forward":
                old_name = step.parameters["old_name"]
                new_name = step.parameters["new_name"]
                if old_name in result:
                    result[new_name] = result.pop(old_name)
            else:
                new_name = step.parameters["new_name"]
                old_name = step.parameters["old_name"]
                if new_name in result:
                    result[old_name] = result.pop(new_name)

        elif step.transformation_type == "custom":
            # Custom migrations must provide deterministic transform
            transform = step.parameters.get("transform")
            if transform:
                result = transform(result, direction)

        return result

    def migrate_data(
        self,
        data: Dict[str, Any],
        from_fp: str,
        to_fp: str,
        direction: str = "forward",
    ) -> Dict[str, Any]:
        """Migrate data across a chain of registered migrations.

        Explicit path required. No automatic inference.
        """
        path = self.find_migration_path(from_fp, to_fp)
        if not path:
            raise ValueError(f"No migration path from {from_fp} to {to_fp}")

        result = data
        for step in path:
            result = self.apply_migration(result, step, direction)
        return result

    def migrate_data_safe(
        self,
        data: Dict[str, Any],
        from_fp: str,
        to_fp: str,
        direction: str = "forward",
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Migrate data with validation and error collection.

        Returns (result, errors). If errors, result may be partial.
        """
        path = self.find_migration_path(from_fp, to_fp)
        if not path:
            return data, [f"no_migration_path: {from_fp} -> {to_fp}"]

        errors: List[str] = []
        result = data
        for step in path:
            try:
                result = self.apply_migration(result, step, direction)
            except Exception as exc:
                errors.append(f"migration_failed: {step.migration_id}: {exc}")

        return result, errors
