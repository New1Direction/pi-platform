from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ZOOM_OUT_STRICT_MODE")


class ZoomOutInput(BaseModel):
    file_path: str = Field(..., description="File path to analyze")
    code_content: str = Field(..., description="File content")


class ZoomOutOutput(BaseModel):
    is_secure: bool = Field(..., description="True if architectural zoom out parsed successfully")
    imports: List[str] = Field(default_factory=list, description="Extracted import packages")
    architecture_summary: str = Field(..., description="System context explanation")
    status: str = Field(..., description="Status (PASSED, REJECTED_ZOOM_OUT, WARN_ZOOM_OUT)")


class PiZoomOutSystemExplainer:
    """Deterministic micro-agent that extracts file imports to explain architectural dependencies."""

    def __init__(self) -> None:
        self.agent_name = "PiZoomOutSystemExplainer"

    def explain_system(self, input_envelope: ZoomOutInput) -> ZoomOutOutput:
        code = input_envelope.code_content
        imports = []

        # Regex to find imports
        lines = code.splitlines()
        for line in lines:
            match = re.match(r"^\s*(?:import\s+([\w\.-]+)|from\s+([\w\.-]+)\s+import)", line)
            if match:
                pkg = match.group(1) or match.group(2)
                if pkg and pkg not in imports:
                    imports.append(pkg)

        is_secure = len(imports) < 15  # Alert if a single file has too many external package dependencies

        summary = f"File imports {len(imports)} packages. Key dependencies: {', '.join(imports[:5])}"

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_ZOOM_OUT"
            else:
                status = "WARN_ZOOM_OUT"
                is_secure = True

        return ZoomOutOutput(is_secure=is_secure, imports=imports, architecture_summary=summary, status=status)
