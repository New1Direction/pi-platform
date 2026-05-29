from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_DEPRECIATION_STRICT_MODE")


class DepreciationInput(BaseModel):
    file_path: str = Field(..., description="Path of the file being audited")
    code_content: str = Field(..., description="Source code content")
    deprecated_patterns: List[str] = Field(
        ..., description="List of deprecated function, class, or module names to flag"
    )


class DepreciationOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no deprecated symbols are found")
    symbols_found: List[str] = Field(default_factory=list, description="List of deprecated elements found")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status of the audit")


class PiDepreciationScanner:
    """Deterministic micro-agent that scans code files for deprecated functions, libraries, or modules."""

    def __init__(self) -> None:
        self.agent_name = "PiDepreciationScanner"

    def scan_depreciation(self, input_envelope: DepreciationInput) -> DepreciationOutput:
        code = input_envelope.code_content
        deprecated_patterns = input_envelope.deprecated_patterns
        symbols_found = []

        lines = code.splitlines()
        for _idx, line in enumerate(lines, start=1):
            # Check for each deprecated pattern
            for pat in deprecated_patterns:
                # Use word boundary or direct search depending on pattern
                regex = r"\b" + re.escape(pat) + r"\b"
                if re.search(regex, line):
                    symbols_found.append(pat)

        is_secure = len(symbols_found) == 0
        risk_score = 60.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_DEPRECIATION"
            else:
                status = "WARN_DEPRECIATION"
                is_secure = True

        return DepreciationOutput(
            is_secure=is_secure, symbols_found=symbols_found, risk_score=risk_score, status=status
        )
