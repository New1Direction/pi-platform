from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class ContractInput(BaseModel):
    openapi_snippet: str = Field(..., description="OpenAPI specification snippet (JSON or YAML format)")
    required_fields: List[str] = Field(..., description="List of required top-level or structural keywords")


class ContractOutput(BaseModel):
    is_valid: bool = Field(..., description="Indicates if contract conforms to requirements")
    missing_fields: List[str] = Field(default_factory=list, description="List of missing required fields")
    status: str = Field(..., description="Contract validation status")


class PiApiContractValidator:
    """Validates that an OpenAPI snippet contains required fields and structure."""

    def __init__(self) -> None:
        self.agent_name = "PiApiContractValidator"

    def validate_contract(self, input_envelope: ContractInput) -> ContractOutput:
        snippet = input_envelope.openapi_snippet
        required = input_envelope.required_fields

        missing = []
        for field in required:
            # Check for structural patterns: e.g., "openapi:", '"openapi"', "/paths", etc.
            # Handles YAML (field:) and JSON ("field":) simple presence checks.
            yaml_pattern = f"{field}:"
            json_pattern = f'"{field}"'
            if yaml_pattern not in snippet and json_pattern not in snippet and field not in snippet:
                missing.append(field)

        is_valid = len(missing) == 0
        status = "CONTRACT_VALID" if is_valid else "CONTRACT_VIOLATION"

        return ContractOutput(is_valid=is_valid, missing_fields=missing, status=status)
