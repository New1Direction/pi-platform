from __future__ import annotations

import re
from typing import Dict, List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_DIMENSIONAL_STRICT_MODE")


class DimensionalAnalysisInput(BaseModel):
    file_path: str = Field(..., description="Source file path")
    source_code: str = Field(..., description="Source code containing arithmetic operations")
    unit_registry: Dict[str, str] = Field(
        ..., description="Mapping of variables to their units (e.g. 'balances[msg.sender]': 'wei', 'rate': 'gwei')"
    )


class DimensionalAnalysisOutput(BaseModel):
    is_secure: bool = Field(..., description="True if all operations maintain dimensional correctness")
    mismatches: List[str] = Field(default_factory=list, description="Lines featuring dimension or unit collisions")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status (PASSED, WARN_DIMENSION_RISK, REJECTED_DIMENSION_RISK)")


class PiDimensionalAnalysisSentry:
    """Specialized financial & unit governance micro-agent."""

    def __init__(self) -> None:
        self.agent_name = "PiDimensionalAnalysisSentry"

    def audit_dimensions(self, input_envelope: DimensionalAnalysisInput) -> DimensionalAnalysisOutput:
        code = input_envelope.source_code
        registry = input_envelope.unit_registry
        mismatches = []

        for idx, line in enumerate(code.splitlines(), 1):
            # Scan for math assignments (e.g., a = b + c)
            if "=" in line and any(op in line for op in ["+", "-", "*", "/"]):
                matched_vars = [var for var in registry.keys() if re.search(r"\b" + re.escape(var) + r"\b", line)]
                if len(matched_vars) > 1:
                    # Check if units differ
                    first_unit = registry[matched_vars[0]]
                    for var in matched_vars[1:]:
                        if registry[var] != first_unit:
                            mismatches.append(
                                f"L{idx}: Mixed units in expression: '{matched_vars[0]}' ({first_unit}) "
                                f"vs '{var}' ({registry[var]}) in: {line.strip()}"
                            )

        is_secure = len(mismatches) == 0
        risk_score = 85.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            status = "REJECTED_DIMENSION_RISK" if is_strict_mode() else "WARN_DIMENSION_RISK"
            if not is_strict_mode():
                is_secure = True

        return DimensionalAnalysisOutput(
            is_secure=is_secure, mismatches=mismatches, risk_score=risk_score, status=status
        )
