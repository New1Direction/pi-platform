from __future__ import annotations

import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_MOCK_TAINT_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class MockDataTaintingInput(BaseModel):
    file_path: str = Field(..., description="Path of the mock or fixture file being audited")
    data_content: str = Field(..., description="Content of the file")


class MockDataTaintingOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no real-looking credentials or production hosts are found")
    tainted_elements: List[str] = Field(default_factory=list, description="List of tainted/sensitive elements found")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status of the audit")


class PiMockDataTaintingSentry:
    """Deterministic micro-agent that checks mock or fixture files to prevent sensitive data leakage."""

    def __init__(self) -> None:
        self.agent_name = "PiMockDataTaintingSentry"

    def check_mock_tainting(self, input_envelope: MockDataTaintingInput) -> MockDataTaintingOutput:
        content = input_envelope.data_content
        tainted_elements = []

        # Patterns for highly sensitive credentials or live resources in mock files
        patterns = [
            (r"\bAKIA[A-Z0-9]{16}\b", "Potential AWS Access Key found"),
            (r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b", "Potential GitHub Token found"),
            (r"\bprod(?:uction)?\.[a-z0-9\-]+\.[a-z]{2,6}\b", "Reference to potential live production environment"),
            (
                r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
                "Internal private IP found",
            ),
            # Match high-entropy values like API keys
            (r"\b[a-zA-Z0-9_\-]{32,}\b", "High-entropy API key or secret token found"),
        ]

        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            for pat, desc in patterns:
                # For private IPs/API keys, make sure it's not a common standard string
                matches = re.findall(pat, line)
                for m in matches:
                    # Skip common mock phrases or localhost/test strings
                    if any(x in m.lower() for x in ["localhost", "127.0.0.1", "mock", "dummy", "test"]):
                        continue
                    if "example" in m.lower() and not m.startswith("AKIA"):
                        continue
                    # Calculate entropy of matching string
                    if len(m) >= 16:
                        unique_chars = len(set(m))
                        entropy_ratio = unique_chars / len(m)
                        # High-entropy check (most random keys have high unique character ratio)
                        if entropy_ratio > 0.45:
                            tainted_elements.append(f"Line {idx}: {desc} ('{m[:10]}...')")
                            break
                    else:
                        tainted_elements.append(f"Line {idx}: {desc} ('{m}')")
                        break

        is_secure = len(tainted_elements) == 0
        risk_score = 85.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_MOCK_TAINT"
            else:
                status = "WARN_MOCK_TAINT"
                is_secure = True

        return MockDataTaintingOutput(
            is_secure=is_secure, tainted_elements=tainted_elements, risk_score=risk_score, status=status
        )
