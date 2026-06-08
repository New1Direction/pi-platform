from __future__ import annotations

import json
import re
from typing import List

from pydantic import BaseModel, Field


class BigQuerySchemaInput(BaseModel):
    schema_json: str = Field(..., description="Raw JSON schema representing BigQuery table structure")
    dataset_id: str = Field(default="", description="Optional GCP dataset ID")
    table_id: str = Field(default="", description="Optional GCP BigQuery table ID")
    check_pii_fields: bool = Field(default=True, description="Whether to scan for sensitive PII field names")


class BigQuerySchemaOutput(BaseModel):
    is_valid: bool = Field(..., description="True if the schema JSON is valid and structurally sound")
    field_count: int = Field(..., description="Total number of fields detected")
    nested_count: int = Field(..., description="Number of nested RECORD or STRUCT fields")
    pii_fields_detected: List[str] = Field(default_factory=list, description="List of detected PII field names")
    issues: List[str] = Field(default_factory=list, description="Identified schema issues")
    risk_score: float = Field(..., description="Calculated schema risk score")
    status: str = Field(..., description="Auditing status: PASS, WARN, or FAIL")


class PiBigQuerySchemaValidator:
    """Validator agent for BigQuery schemas to audit structure, data types, nested records, and PII exposure risks."""

    def __init__(self) -> None:
        self.agent_name = "PiBigQuerySchemaValidator"

    def execute(self, input_envelope: BigQuerySchemaInput) -> BigQuerySchemaOutput:
        schema_json = input_envelope.schema_json
        check_pii_fields = input_envelope.check_pii_fields

        issues = []
        pii_fields_detected = []
        field_count = 0
        nested_count = 0
        risk_score = 0.0

        # Try to parse the JSON
        try:
            parsed = json.loads(schema_json)
        except json.JSONDecodeError as e:
            issues.append(f"Failed to parse JSON schema: {str(e)}")
            return BigQuerySchemaOutput(
                is_valid=False,
                field_count=0,
                nested_count=0,
                pii_fields_detected=[],
                issues=issues,
                risk_score=50.0,
                status="FAIL",
            )

        # The parsed schema can be a list directly, or a dictionary with a "fields" list
        fields_list = None
        if isinstance(parsed, list):
            fields_list = parsed
        elif isinstance(parsed, dict):
            if "fields" in parsed and isinstance(parsed["fields"], list):
                fields_list = parsed["fields"]
            else:
                issues.append("Schema JSON must be a list of fields or a dict with a 'fields' list.")
                return BigQuerySchemaOutput(
                    is_valid=False,
                    field_count=0,
                    nested_count=0,
                    pii_fields_detected=[],
                    issues=issues,
                    risk_score=30.0,
                    status="FAIL",
                )
        else:
            issues.append("Schema JSON must be a list or a dict.")
            return BigQuerySchemaOutput(
                is_valid=False,
                field_count=0,
                nested_count=0,
                pii_fields_detected=[],
                issues=issues,
                risk_score=30.0,
                status="FAIL",
            )

        valid_types = {
            "STRING",
            "INTEGER",
            "INT64",
            "FLOAT",
            "FLOAT64",
            "BOOLEAN",
            "BOOL",
            "BYTES",
            "DATE",
            "DATETIME",
            "TIME",
            "TIMESTAMP",
            "RECORD",
            "STRUCT",
            "NUMERIC",
            "BIGNUMERIC",
            "JSON",
            "GEOGRAPHY",
        }
        valid_modes = {"NULLABLE", "REQUIRED", "REPEATED"}

        pii_keywords = [
            "email",
            "phone",
            "ssn",
            "password",
            "credit_card",
            "card_number",
            "dob",
            "birth_date",
            "address",
            "ip_address",
            "user_id",
            "national_id",
            "passport",
            "license_plate",
            "salary",
            "account_number",
        ]

        def validate_fields(fields: List[dict]) -> tuple[int, int]:
            nonlocal risk_score
            f_count = 0
            n_count = 0

            for idx, field_item in enumerate(fields):
                if not isinstance(field_item, dict):
                    issues.append(f"Field at index {idx} is not a dictionary.")
                    risk_score += 15.0
                    continue

                f_count += 1
                name = field_item.get("name")
                field_type = field_item.get("type")
                mode = field_item.get("mode", "NULLABLE")

                if not name:
                    issues.append(f"Field at index {idx} is missing 'name'.")
                    risk_score += 15.0
                    continue
                if not field_type:
                    issues.append(f"Field '{name}' is missing 'type'.")
                    risk_score += 15.0
                    continue

                # Check field name format
                if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", name) or len(name) > 300:
                    issues.append(f"Field name '{name}' violates naming standards (invalid characters or too long).")
                    risk_score += 10.0

                # Check field type validity
                upper_type = str(field_type).upper()
                if upper_type not in valid_types:
                    issues.append(f"Field '{name}' has invalid type '{field_type}'.")
                    risk_score += 15.0

                # Check mode validity
                upper_mode = str(mode).upper()
                if upper_mode not in valid_modes:
                    issues.append(f"Field '{name}' has invalid mode '{mode}'.")
                    risk_score += 10.0

                # Increment nested count if RECORD/STRUCT
                if upper_type in ["RECORD", "STRUCT"]:
                    n_count += 1
                    nested_fields = field_item.get("fields")
                    if nested_fields and isinstance(nested_fields, list):
                        sub_f, sub_n = validate_fields(nested_fields)
                        f_count += sub_f
                        n_count += sub_n
                    elif not nested_fields and upper_type in ["RECORD", "STRUCT"]:
                        issues.append(f"Field '{name}' of type {upper_type} must contain a list of 'fields'.")
                        risk_score += 15.0

                # Detect PII exposure
                if check_pii_fields:
                    lower_name = name.lower()
                    if any(kw in lower_name for kw in pii_keywords):
                        pii_fields_detected.append(name)
                        if upper_mode == "REQUIRED":
                            issues.append(f"PII field '{name}' is in REQUIRED mode, posing high exposure risk.")
                            risk_score += 20.0
                        else:
                            issues.append(f"PII field '{name}' detected (mode: {mode}).")
                            risk_score += 10.0

            return f_count, n_count

        field_count, nested_count = validate_fields(fields_list)
        risk_score = min(risk_score, 100.0)

        # is_valid is False if there are critical errors
        critical_indicators = [
            "missing 'name'",
            "missing 'type'",
            "invalid type",
            "is not a dictionary",
            "must contain a list of 'fields'",
        ]
        is_valid = not any(any(ind in issue for ind in critical_indicators) for issue in issues)

        if not is_valid or risk_score > 60.0:
            status = "FAIL"
        elif risk_score >= 30.0:
            status = "WARN"
        else:
            status = "PASS"

        return BigQuerySchemaOutput(
            is_valid=is_valid,
            field_count=field_count,
            nested_count=nested_count,
            pii_fields_detected=pii_fields_detected,
            issues=issues,
            risk_score=risk_score,
            status=status,
        )
