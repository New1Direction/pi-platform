from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_DEAD_CODE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class DeadCodeInput(BaseModel):
    file_path: str = Field(..., description="Path of the file being audited")
    code_content: str = Field(..., description="Source code content")


class DeadCodeOutput(BaseModel):
    is_secure: bool = Field(
        ..., description="True if no dead code (e.g. unused imports or unreachable statements) is detected"
    )
    unused_tokens: List[str] = Field(default_factory=list, description="List of dead code occurrences found")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status of the audit")


class PiDeadCodePruner:
    """Deterministic micro-agent that scans files for dead code, unused imports, or unreachable lines."""

    def __init__(self) -> None:
        self.agent_name = "PiDeadCodePruner"

    def prune_dead_code(self, input_envelope: DeadCodeInput) -> DeadCodeOutput:
        code = input_envelope.code_content
        unused_tokens = []

        lines = code.splitlines()

        # 1. Check for unused imports
        import_pattern = r"^\s*(?:import\s+([a-zA-Z0-9_]+)|from\s+[a-zA-Z0-9_\.]+\s+import\s+([a-zA-Z0-9_]+))"
        for idx, line in enumerate(lines, start=1):
            match = re.match(import_pattern, line)
            if match:
                imported_name = match.group(1) or match.group(2)
                if imported_name:
                    # Search for occurrences of this imported name in the rest of the file
                    # We look for word boundaries around imported_name
                    occurrences = 0
                    for l_idx, current_line in enumerate(lines, start=1):
                        if l_idx == idx:
                            continue
                        if re.search(r"\b" + re.escape(imported_name) + r"\b", current_line):
                            occurrences += 1
                    if occurrences == 0:
                        unused_tokens.append(f"Line {idx}: Unused import '{imported_name}'")

        # 2. Check for unreachable code after return/raise
        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # If line is 'return ...' or 'raise ...', check if next line is in the same indentation block and not empty
            if stripped.startswith("return") or stripped.startswith("raise"):
                if idx < len(lines):
                    next_line = lines[idx]
                    next_stripped = next_line.strip()
                    if (
                        next_stripped
                        and not next_stripped.startswith("#")
                        and not next_stripped.startswith("def ")
                        and not next_stripped.startswith("class ")
                        and not next_stripped.startswith("elif")
                        and not next_stripped.startswith("else")
                        and not next_stripped.startswith("except")
                        and not next_stripped.startswith("finally")
                    ):
                        # Check if next line indentation is equal to or greater than the current line
                        current_indent = len(line) - len(line.lstrip())
                        next_indent = len(next_line) - len(next_line.lstrip())
                        if next_indent >= current_indent:
                            unused_tokens.append(f"Line {idx + 1}: Unreachable statement after return/raise")

        is_secure = len(unused_tokens) == 0
        risk_score = 50.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_DEAD_CODE"
            else:
                status = "WARN_DEAD_CODE"
                is_secure = True

        return DeadCodeOutput(is_secure=is_secure, unused_tokens=unused_tokens, risk_score=risk_score, status=status)
