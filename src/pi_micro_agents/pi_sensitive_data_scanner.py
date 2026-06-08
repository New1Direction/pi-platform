from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field


class SensitiveDataInput(BaseModel):
    data_label: str = Field(..., description="Label or category of data payload being scanned")
    text_content: str = Field(..., description="Raw text content to check for PII or sensitive keys")


class SensitiveDataOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no unauthorized PII elements were identified")
    discovered_pii_elements: List[str] = Field(
        default_factory=list, description="List of detected PII or sensitive elements"
    )
    risk_score: float = Field(..., description="Calculated security risk score from 0.0 to 100.0")
    status: str = Field(..., description="Operational compliance status")


class PiSensitiveDataScanner:
    """Specialized PII and Sensitive Data Scanner searching for emails, SSNs, credit cards, and key files."""

    def __init__(self) -> None:
        self.agent_name = "PiSensitiveDataScanner"

    def scan_sensitive_data(self, input_envelope: SensitiveDataInput) -> SensitiveDataOutput:
        content = input_envelope.text_content
        findings = []
        risk_score = 0.0

        # Scan for Social Security Number (SSN)
        ssn_re = re.compile(r"\b\d{3}-\d{2}-\d{4}\b|\bssn\b", re.IGNORECASE)
        if ssn_re.search(content):
            findings.append("SSN Leak")
            risk_score += 50.0

        # Scan for Email addresses
        email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
        if email_re.search(content):
            findings.append("Email Leak")
            risk_score += 20.0

        # Scan for credit card structures
        cc_re = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
        if cc_re.search(content):
            # Exclude standard phone number length formats if possible or verify
            cleaned_cc = re.sub(r"[ -]", "", cc_re.search(content).group(0))
            if len(cleaned_cc) in [15, 16] and not cleaned_cc.startswith("000"):
                findings.append("Credit Card Leak")
                risk_score += 45.0

        risk_score = min(risk_score, 100.0)
        is_secure = risk_score < 40.0
        status = "FLAGGED" if not is_secure else "PASSED"

        return SensitiveDataOutput(
            is_secure=is_secure, discovered_pii_elements=findings, risk_score=risk_score, status=status
        )
