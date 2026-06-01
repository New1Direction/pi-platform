from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field


class HardcodedSecretInput(BaseModel):
    file_path: str = Field(..., description="Path to the file under inspection")
    file_content: str = Field(..., description="Raw text content of the file")


class HardcodedSecretOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no hardcoded keys or secrets are identified")
    flagged_secrets: List[str] = Field(default_factory=list, description="List of flagged secret patterns or locations")
    risk_score: float = Field(..., description="Vulnerability severity risk rating from 0.0 to 100.0")
    status: str = Field(..., description="Security classification status")


class PiHardcodedSecretDetector:
    """Specialized static analysis agent to detect hardcoded secrets, private keys, and API tokens."""

    def __init__(self) -> None:
        self.agent_name = "PiHardcodedSecretDetector"

    def scan_hardcoded_secrets(self, input_envelope: HardcodedSecretInput) -> HardcodedSecretOutput:
        content = input_envelope.file_content
        findings = []
        risk_score = 0.0

        # Regex for SSH/PEM private keys
        if "begin private key" in content.lower() or "begin rsa private key" in content.lower():
            findings.append("Private key block detected inside text.")
            risk_score += 50.0

        # Regex for standard AWS Access Keys and generic tokens
        aws_key_re = re.compile(r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPJ)[A-Z0-9]{16}")
        if aws_key_re.search(content):
            findings.append("AWS IAM Credentials/Access Key ID detected.")
            risk_score += 45.0

        # Generic credentials assignments (e.g. password = "...", api_key = "...")
        cred_re = re.compile(
            r"(?i)\b(password|passwd|secret|api_key|apikey|token|private_key|client_secret)\s*=\s*['\"]([^'\"]{8,})['\"]"
        )
        matches = cred_re.findall(content)
        for var, val in matches:
            # Skip placeholders
            if any(p in val.lower() for p in ["placeholder", "your_", "insert_", "dummy", "test_value", "123", "abc"]):
                continue
            findings.append(f"Hardcoded assignment to sensitive keyword '{var}' found.")
            risk_score += 35.0

        risk_score = min(risk_score, 100.0)
        is_secure = risk_score < 40.0
        status = "FLAGGED" if not is_secure else "PASSED"

        return HardcodedSecretOutput(
            is_secure=is_secure, flagged_secrets=findings, risk_score=risk_score, status=status
        )
