from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field


class DateInput(BaseModel):
    content: str = Field(..., description="String contents of the document or dataset")


class DateOutput(BaseModel):
    consistent_format: bool = Field(..., description="True if only one distinct date format style is found")
    formats_found: List[str] = Field(default_factory=list, description="List of unique date format styles identified")
    status: str = Field(..., description="Date format consistency status")


class PiDateFormatConsistencyChecker:
    """Ensures all date strings in a file use the same format."""

    def __init__(self) -> None:
        self.agent_name = "PiDateFormatConsistencyChecker"

    def check_date_consistency(self, input_envelope: DateInput) -> DateOutput:
        content = input_envelope.content

        # Standard date patterns and labels
        patterns = {
            "ISO-8601 (YYYY-MM-DD)": r"\b\d{4}-\d{2}-\d{2}\b",
            "US-Slash (MM/DD/YYYY)": r"\b\d{2}/\d{2}/\d{4}\b",
            "Euro-Dash (DD-MM-YYYY)": r"\b\d{2}-\d{2}-\d{4}\b",
            "Text-Month (DD Month YYYY)": r"\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{4}\b",
        }

        formats_found = []
        for name, pattern in patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                formats_found.append(name)

        # File is consistent if 0 or 1 format is found
        consistent = len(formats_found) <= 1
        status = "DATE_FORMAT_CONSISTENT" if consistent else "DATE_FORMAT_INCONSISTENT"

        return DateOutput(consistent_format=consistent, formats_found=formats_found, status=status)
