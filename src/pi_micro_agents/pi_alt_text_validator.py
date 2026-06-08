from __future__ import annotations

import re

from pydantic import BaseModel, Field


class HtmlInput(BaseModel):
    content: str = Field(..., description="String contents of the HTML/JSX layout file")


class AltOutput(BaseModel):
    missing_alt_count: int = Field(..., description="Count of img elements lacking an alt attribute")
    status: str = Field(..., description="Accessibility validation status")


class PiAltTextValidator:
    """Scans HTML/JSX for <img> tags missing alt attributes."""

    def __init__(self) -> None:
        self.agent_name = "PiAltTextValidator"

    def validate_alt_text(self, input_envelope: HtmlInput) -> AltOutput:
        content = input_envelope.content

        # Match <img> tags in HTML or JSX:
        # e.g., <img src="..." />
        img_tags = re.findall(r"<img\b[^>]*>", content, re.IGNORECASE)

        missing_count = 0
        for tag in img_tags:
            # Check if "alt" is defined in the tag properties
            # alt can be empty (alt=""), but let's count those missing or with just whitespace
            alt_match = re.search(r"\balt\s*=\s*['\"]([^'\"]*)['\"]", tag, re.IGNORECASE)
            # JSX match (e.g. alt={...})
            alt_jsx_match = re.search(r"\balt\s*=\s*\{[^}]*\}", tag, re.IGNORECASE)

            if not alt_match and not alt_jsx_match:
                missing_count += 1
            elif alt_match and not alt_match.group(1).strip():
                # Present but completely empty / whitespace
                missing_count += 1

        status = "ACCESSIBILITY_VIOLATION" if missing_count > 0 else "ACCESSIBILITY_COMPLIANT"

        return AltOutput(missing_alt_count=missing_count, status=status)
