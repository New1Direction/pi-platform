from __future__ import annotations

import json
import math
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_GIT_SECRET_ENTROPY_LEAK_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class GitSecretEntropyLeakInput(BaseModel):
    file_path: str = Field(..., description="The codebase file path to check")
    code_content: str = Field(..., description="File contents to analyze for high-entropy secrets")
    check_level: str = Field(default="STRICT", description="Strictness level")


class GitSecretEntropyLeakOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if no high-entropy leaks are found")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable lines or keywords")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiGitSecretEntropyLeakSentry:
    """Specialized Infrastructure micro-agent that analyzes codebase changes for high-entropy password/key strings."""

    def __init__(self) -> None:
        self.agent_name = "PiGitSecretEntropyLeakSentry"

    def calculate_shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def audit_entropy_leaks(self, input_envelope: GitSecretEntropyLeakInput) -> GitSecretEntropyLeakOutput:
        code = input_envelope.code_content
        vulnerable_elements = []
        flagged_findings = []

        # Find quoted strings that look like keys/tokens
        quoted_strings = re.findall(r'["\']([a-zA-Z0-9_\-\.\=\+]{16,})["\']', code)

        for s in quoted_strings:
            entropy = self.calculate_shannon_entropy(s)
            # Standard threshold for high-entropy password/private key is ~4.5
            if entropy > 4.5:
                # Exclude standard safe strings
                if any(ignored in s.lower() for ignored in ["bootstrap", "tailwind", "class", "href", "http", "sha"]):
                    continue
                vulnerable_elements.append(s[:10])
                flagged_findings.append(
                    f"High-entropy string detected: '{s[:12]}...' (Entropy: {entropy:.2f}). "
                    "This pattern frequently indicates embedded secret keys, private credentials, or programmatic passwords."
                )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_GIT_SECRET_ENTROPY_LEAK"
            else:
                status = "WARN_GIT_SECRET_ENTROPY_LEAK"
                is_secure = True

        return GitSecretEntropyLeakOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
