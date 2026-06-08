from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field


class CodeInput(BaseModel):
    content: str = Field(..., description="String contents of the source file")


class SleepOutput(BaseModel):
    has_sleep: bool = Field(..., description="Indicates if any hardcoded sleep calls exist")
    locations: List[int] = Field(default_factory=list, description="List of line numbers containing sleep calls")
    status: str = Field(..., description="Sleep detection status")


class PiHardcodedSleepDetector:
    """Finds hardcoded sleep(), time.sleep(), or equivalent calls."""

    def __init__(self) -> None:
        self.agent_name = "PiHardcodedSleepDetector"

    def detect_sleeps(self, input_envelope: CodeInput) -> SleepOutput:
        content = input_envelope.content
        lines = content.splitlines()

        # Match time.sleep, asyncio.sleep, sleep(, Thread.sleep, etc.
        patterns = [
            r"\btime\.sleep\s*\(",
            r"\basyncio\.sleep\s*\(",
            r"\bThread\.sleep\s*\(",
            r"\bawait\s+sleep\s*\(",
            r"\b\.sleep\s*\(\s*\d+",
        ]

        locations = []
        for idx, line in enumerate(lines, start=1):
            # Skip comments or imports
            cleaned_line = line.split("#")[0].strip()
            if cleaned_line.startswith(("import ", "from ")):
                continue

            for pattern in patterns:
                if re.search(pattern, cleaned_line):
                    locations.append(idx)
                    break

        has_sleep = len(locations) > 0
        status = "SLEEP_CALLS_DETECTED" if has_sleep else "NO_SLEEP_CALLS"

        return SleepOutput(has_sleep=has_sleep, locations=locations, status=status)
