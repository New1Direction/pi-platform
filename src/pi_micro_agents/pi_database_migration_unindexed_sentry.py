from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_DATABASE_MIGRATION_UNINDEXED_STRICT_MODE")


class DatabaseMigrationUnindexedInput(BaseModel):
    file_path: str = Field(..., description="Migration or schema file path")
    migration_code: str = Field(..., description="Migration source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class DatabaseMigrationUnindexedOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if all foreign keys or search fields are indexed")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable table or column names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiDatabaseMigrationUnindexedSentry:
    """Specialized database micro-agent that audits migration scripts for foreign keys or search fields missing indexes."""

    def __init__(self) -> None:
        self.agent_name = "PiDatabaseMigrationUnindexedSentry"

    def audit_migration_indexes(
        self, input_envelope: DatabaseMigrationUnindexedInput
    ) -> DatabaseMigrationUnindexedOutput:
        code = input_envelope.migration_code
        vulnerable_elements = []
        flagged_findings = []

        # Find column additions or creations containing foreign keys or id suffix (e.g. user_id, customer_id, references, foreign_key)
        # Matches patterns like user_id INT, references :users, ForeignKey(something)
        lines = code.splitlines()
        for idx, line in enumerate(lines, 1):
            clean_line = line.strip()
            if (
                "foreign_key" in clean_line.lower()
                or "references" in clean_line.lower()
                or re.search(r"\b[a-zA-Z0-9_]+_id\b", clean_line.lower())
            ):
                # Check if this line has index/index: true or if there is an index created in the migration body
                # Simple check: if index/key/unique is not found in the same line or migration block
                if not any(idx_kw in code.lower() for idx_kw in ["index", "add_index", "create index", "unique_key"]):
                    vulnerable_elements.append(f"Line {idx}")
                    flagged_findings.append(
                        f"Line {idx}: Potential foreign key or search field missing index: '{clean_line}'. "
                        "Omitting indexes on foreign keys leads to serious table-scan performance degradation during joins or deletes."
                    )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 60.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_DATABASE_MIGRATION_UNINDEXED"
            else:
                status = "WARN_DATABASE_MIGRATION_UNINDEXED"
                is_secure = True

        return DatabaseMigrationUnindexedOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
