from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_SEMANTIC_SCHEMA_REGIST_STRICT_MODE")


class SemanticSchemaRegistryInput(BaseModel):
    file_path: str = Field(..., description="Schema or migration file path")
    schema_code: str = Field(..., description="File content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class SemanticSchemaRegistryOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if semantic schema checks passed")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable table or field definitions")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSemanticSchemaRegistry:
    """Specialized database micro-agent that audits migrations or schemas for dynamic column shifts lacking integrity bounds."""

    def __init__(self) -> None:
        self.agent_name = "PiSemanticSchemaRegistry"

    def audit_schema_registry(self, input_envelope: SemanticSchemaRegistryInput) -> SemanticSchemaRegistryOutput:
        code = input_envelope.schema_code
        vulnerable_elements = []
        flagged_findings = []

        # Find dynamic schema shifts, unstructured fields with wildcards, or lack of primary constraints
        # E.g. raw JSON field types or wildcards in schema validations that allow arbitrary inputs
        unstructured_match = re.search(
            r"(JSON1|dynamic_schema|unstructured_data|Column\(\s*JSON\s*\)|BypassValidation)", code
        )

        if unstructured_match:
            vulnerable_elements.append(unstructured_match.group(1))
            flagged_findings.append(
                f"Schema definition uses an unconstrained dynamic columns configuration: '{unstructured_match.group(1)}'. "
                f"Allowing arbitrary unstructured column inputs without strict type bounds triggers payload injection "
                f"or downstream query injection exploits."
            )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 60.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SCHEMA_REGISTRY"
            else:
                status = "WARN_SCHEMA_REGISTRY"
                is_secure = True

        return SemanticSchemaRegistryOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
