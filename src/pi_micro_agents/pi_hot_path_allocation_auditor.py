from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_PERF_STRICT_MODE")


class HotPathAllocationInput(BaseModel):
    file_path: str = Field(..., description="Source code file path")
    source_code: str = Field(..., description="C# or Python source code")
    hot_path_lines: List[int] = Field(
        default_factory=list, description="Line indices known to be in performance hot paths"
    )


class HotPathAllocationOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no allocation anti-patterns exist on hot paths")
    flagged_hotspots: List[str] = Field(default_factory=list, description="Details of allocation anti-patterns flagged")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status (PASSED, WARN_PERF_RISK, REJECTED_PERF_RISK)")


class PiHotPathAllocationAuditor:
    """Specialized high-performance diagnostics micro-agent."""

    def __init__(self) -> None:
        self.agent_name = "PiHotPathAllocationAuditor"

    def audit_hot_path(self, input_envelope: HotPathAllocationInput) -> HotPathAllocationOutput:
        code = input_envelope.source_code
        hot_lines = set(input_envelope.hot_path_lines)
        hotspots = []

        # Anti-pattern regexes
        patterns = {
            r"\.ToLower\(\)": "ToLower() allocates a new string copy. Consider OrdinalIgnoreCase comparisons.",
            r"\.Substring\(": "Substring() allocates a new string object. Use Span<T> or Memory<T> slices.",
            r"new\s+Dictionary<": "Per-call instantiation of dictionary within path. Hoist or cache as FrozenDictionary.",
            r"Regex\(": "Non-compiled Regex instantiation in path. Hoist to static or use [GeneratedRegex].",
        }

        for idx, line in enumerate(code.splitlines(), 1):
            # Only check if lines list is empty (check all) or if this line is in the hot lines list
            if not hot_lines or idx in hot_lines:
                for pattern, desc in patterns.items():
                    if re.search(pattern, line):
                        hotspots.append(f"L{idx}: allocation-risk: {desc} -> '{line.strip()}'")

        is_secure = len(hotspots) == 0
        risk_score = 75.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            status = "REJECTED_PERF_RISK" if is_strict_mode() else "WARN_PERF_RISK"
            if not is_strict_mode():
                is_secure = True

        return HotPathAllocationOutput(
            is_secure=is_secure, flagged_hotspots=hotspots, risk_score=risk_score, status=status
        )
