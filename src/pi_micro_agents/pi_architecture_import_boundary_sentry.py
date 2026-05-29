from __future__ import annotations

import os
import re
from typing import Dict, List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_IMPORT_BOUNDARY_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class ImportBoundaryInput(BaseModel):
    file_path: str = Field(..., description="Path of the file being audited")
    code_content: str = Field(..., description="Source code content")
    forbidden_mappings: Dict[str, List[str]] = Field(
        ..., description="Dictionary mapping file path substrings to list of forbidden import module patterns"
    )


class ImportBoundaryOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no import boundary violations are found")
    violated_imports: List[str] = Field(default_factory=list, description="List of boundary violating imports found")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status of the audit")


class PiArchitectureImportBoundarySentry:
    """Deterministic micro-agent that audits import lines to prevent cross-layer architectural boundary violations."""

    def __init__(self) -> None:
        self.agent_name = "PiArchitectureImportBoundarySentry"

    def check_import_boundaries(self, input_envelope: ImportBoundaryInput) -> ImportBoundaryOutput:
        file_path = input_envelope.file_path
        code = input_envelope.code_content
        forbidden_mappings = input_envelope.forbidden_mappings
        violated_imports = []

        # Find matching keys in forbidden_mappings
        matching_rules = []
        for key, forbidden_patterns in forbidden_mappings.items():
            if key in file_path:
                matching_rules.append((key, forbidden_patterns))

        if matching_rules:
            # Parse imports using regular expressions
            # Matches: 'import module', 'import module as alias', 'from module import ...'
            import_patterns = [r"^\s*import\s+([a-zA-Z0-9_\.]+)", r"^\s*from\s+([a-zA-Z0-9_\.]+)\s+import"]

            lines = code.splitlines()
            for idx, line in enumerate(lines, start=1):
                for pat in import_patterns:
                    match = re.match(pat, line)
                    if match:
                        imported_module = match.group(1)
                        for key, forbidden_patterns in matching_rules:
                            for forbidden in forbidden_patterns:
                                forbidden_norm = forbidden.replace("/", ".").strip(".")
                                module_norm = imported_module.replace("/", ".").strip(".")
                                if forbidden_norm in module_norm:
                                    violated_imports.append(
                                        f"Line {idx}: Import '{imported_module}' violates boundary rule for '{key}' (forbidden: '{forbidden}')"
                                    )

        is_secure = len(violated_imports) == 0
        risk_score = 90.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_IMPORT_BOUNDARY"
            else:
                status = "WARN_IMPORT_BOUNDARY"
                is_secure = True

        return ImportBoundaryOutput(
            is_secure=is_secure, violated_imports=violated_imports, risk_score=risk_score, status=status
        )
