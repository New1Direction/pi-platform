from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field


class StringInput(BaseModel):
    content: str = Field(..., description="String contents of the source file")
    language: str = Field(default="python", description="Programming language context")


class StringOutput(BaseModel):
    hardcoded_count: int = Field(..., description="Count of hardcoded literals found")
    locations: List[int] = Field(default_factory=list, description="List of line numbers for violations")
    status: str = Field(..., description="Hardcoded string check status")


class PiHardcodedStringDetector:
    """Flags user-facing strings that are not pulled from translation keys."""

    def __init__(self) -> None:
        self.agent_name = "PiHardcodedStringDetector"

    def detect_hardcoded_strings(self, input_envelope: StringInput) -> StringOutput:
        content = input_envelope.content
        lines = content.splitlines()

        locations = []

        # Find typical hardcoded strings in output or template structures
        # e.g., text: "Welcome to our portal", alert('Welcome'), return "Success"
        # We skip matches wrapped in localization calls like _("Welcome") or translate("Welcome")
        patterns = [
            r"\\balert\\s*\\(\\s*['\\"]([^'\\"]+)['\\"]\\s*\\)",
            r"\\btext\\s*:\\s*['\\"]([^'\\"]+)['\\"]",
            r"\\bplaceholder\\s*=\\s*['\\"]([^'\\"]+)['\\"]",
            r"\\blabel\\s*:\\s*['\\"]([^'\\"]+)['\\"]",
            r"\\btitle\\s*:\\s*['\\"]([^'\\"]+)['\\"]",
        ]

        for idx, line in enumerate(lines, start=1):
            cleaned = line.split("#")[0].strip()

            # Ignore comments, imports, or test descriptions
            if cleaned.startswith(("import ", "from ", "def test_", "class Test")):
                continue

            for pattern in patterns:
                match = re.search(pattern, cl
<truncated 770 bytes