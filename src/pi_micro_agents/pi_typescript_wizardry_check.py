from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_TYPESCRIPT_WIZARDRY_STRICT_MODE")


class TypeScriptWizardryInput(BaseModel):
    code_content: str = Field(..., description="TypeScript source code to audit")


class TypeScriptWizardryOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no TypeScript bad practices/shortcuts are found")
    unsafe_occurrences: List[str] = Field(default_factory=list, description="List of unsafe TypeScript patterns found")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status of the audit")


class PiTypeScriptWizardryCheck:
    """Deterministic micro-agent that checks TypeScript code for bad shortcuts like any or as any."""

    def __init__(self) -> None:
        self.agent_name = "PiTypeScriptWizardryCheck"

    def check_typescript(self, input_envelope: TypeScriptWizardryInput) -> TypeScriptWizardryOutput:
        code = input_envelope.code_content
        unsafe_occurrences = []

        # Look for 'any' types or casting to any
        # e.g., ": any", "<any>", "as any"
        any_patterns = [
            (r":\s*any\b", "Explicit 'any' type annotation found"),
            (r"\bas\s+any\b", "Type assertion 'as any' found"),
            (r"<\s*any\s*>", "Generic/cast '<any>' found"),
            (r"//\s*@ts-ignore", "TypeScript disable comment '@ts-ignore' found"),
            (r"//\s*@ts-nocheck", "TypeScript disable comment '@ts-nocheck' found"),
        ]

        lines = code.splitlines()
        for idx, line in enumerate(lines, start=1):
            # Skip comments to avoid false positives (except the explicit disable comments)
            stripped = line.strip()
            if stripped.startswith("//") and not ("@ts-ignore" in stripped or "@ts-nocheck" in stripped):
                continue
            for pat, msg in any_patterns:
                if re.search(pat, line):
                    unsafe_occurrences.append(f"Line {idx}: {msg}")

        is_secure = len(unsafe_occurrences) == 0
        risk_score = 75.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_TYPESCRIPT_WIZARDRY"
            else:
                status = "WARN_TYPESCRIPT_WIZARDRY"
                is_secure = True

        return TypeScriptWizardryOutput(
            is_secure=is_secure, unsafe_occurrences=unsafe_occurrences, risk_score=risk_score, status=status
        )
