from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_SEMANTIC_SCHEMA_DYNAMIC_FIELD_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class SemanticSchemaDynamicFieldInput(BaseModel):
    file_path: str = Field(..., description="Schema file path")
    schema_code: str = Field(..., description="Schema code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class SemanticSchemaDynamicFieldOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if dynamic columns have nested models")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable table or column definitions")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSemanticSchemaDynamicFieldCheck:
    """Specialized database micro-agent that audits schemas for dynamic or unstructured fields lacking strict sub-models."""

    def __init__(self) -> None:
        self.agent_name = "PiSemanticSchemaDynamicFieldCheck"

    def audit_dynamic_fields(self, input_envelope: SemanticSchemaDynamicFieldInput) -> SemanticSchemaDynamicFieldOutput:
        code = input_envelope.schema_code
        vulnerable_elements = []
        flagged_findings = []

        # Find dynamic raw JSON or Dict columns inside models
        # e.g., JSONColumn, Column(JSON), Column(pickle), Column(text) representing raw serialized data
        matches = re.finditer(
            r"([a-zA-Z0-9_]+)\s*=\s*(?:Column\s*\(\s*(?:JSON|PickleType|text)\s*\)|JSONColumn)", code, re.IGNORECASE
        )

        for match in matches:
            col_name = match.group(1)
            # Check if there is a corresponding subfield schema or pydantic/marshmallow type defined for it
            # Simple check: see if there's any validator or nested type with the same column name prefix/suffix
            has_submodel = any(kw in code for kw in [f"{col_name}_schema", f"{col_name}_model", "Dict[str,"])
            if not has_submodel:
                vulnerable_elements.append(col_name)
                flagged_findings.append(
                    f"Dynamic raw database field '{col_name}' lacks a corresponding nested sub-model or strict type validator. "
                    "Unconstrained dynamic columns permit arbitrary payload insertions, risking NoSQL/SQL injections or application logic bypass."
                )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 65.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SEMANTIC_SCHEMA_DYNAMIC_FIELD"
            else:
                status = "WARN_SEMANTIC_SCHEMA_DYNAMIC_FIELD"
                is_secure = True

        return SemanticSchemaDynamicFieldOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
