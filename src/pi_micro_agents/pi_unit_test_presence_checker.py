from __future__ import annotations

import re

from pydantic import BaseModel, Field


class TestInput(BaseModel):
    file_path: str = Field(..., description="Path of the source file to evaluate")
    content: str = Field(..., description="String contents of the source file")


class TestOutput(BaseModel):
    has_tests: bool = Field(..., description="Indicates if any unit tests are present")
    test_count: int = Field(..., description="Total count of identified test patterns")
    status: str = Field(..., description="Test presence status")


class PiUnitTestPresenceChecker:
    """Detects presence and minimum count of unit test functions in a source file."""

    def __init__(self) -> None:
        self.agent_name = "PiUnitTestPresenceChecker"

    def check_test_presence(self, input_envelope: TestInput) -> TestOutput:
        content = input_envelope.content

        # Simple patterns matching tests across python, javascript/typescript, etc.
        patterns = [
            r"\bdef\s+test_",
            r"\bclass\s+Test",
            r"\bit\s*\(\s*['\"]",
            r"\bdescribe\s*\(\s*['\"]",
            r"\btest\s*\(\s*['\"]",
            r"@pytest\.mark\.",
        ]

        total_count = 0
        for pattern in patterns:
            matches = re.findall(pattern, content)
            total_count += len(matches)

        has_tests = total_count > 0
        status = "TESTS_PRESENT" if has_tests else "NO_TESTS_FOUND"

        return TestOutput(has_tests=has_tests, test_count=total_count, status=status)
