from __future__ import annotations

import re
from typing import List, Tuple

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_LEAK_STRICT_MODE")


# 2. Heuristics scanner for outbound payload data privacy
def detect_leak_anomalies(text: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0
    if not text:
        return 0.0, []

    # A. Credential / Private Key Leaks
    secret_patterns = [
        (r"(?:api_key|apikey|api-key)\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}['\"]", "hardcoded API key"),
        (
            r"(?:private_key|privatekey)\s*[:=]\s*['\"](?:0x)?[a-fA-F0-9]{64,}['\"]",
            "hardcoded private key hex signature",
        ),
        (
            r"(?:secret|client_secret|client-secret)\s*[:=]\s*['\"][a-zA-Z0-9_\-+=/]{30,}['\"]",
            "hardcoded client secret token",
        ),
    ]
    for pat, desc in secret_patterns:
        if re.search(pat, text, re.IGNORECASE):
            violations.append(f"potential leak of secret information: {desc}")
            max_risk = max(max_risk, 95.0)

    # B. Personally Identifiable Information (PII)
    pii_patterns = [
        (
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "Personally Identifiable Information (PII) email leak",
        ),
        (
            r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "Personally Identifiable Information (PII) phone leak",
        ),
    ]
    for pat, desc in pii_patterns:
        if re.search(pat, text):
            violations.append(desc)
            max_risk = max(max_risk, 80.0)

    # C. System Prompt / Instruction Leakage
    system_leak_patterns = [
        (
            r"\byou\s+are\s+a\s+(?:helpful|powerful|agentic|safety|specialized|assistant)\b",
            "system prompt role instruction leakage",
        ),
        (r"\bignore\s+previous\s+instructions\b", "system prompt override leak pattern"),
        (r"\bcore\s+system\s+(?:instructions|guidelines|prompt)\b", "system prompt structural keyword leak"),
    ]
    for pat, desc in system_leak_patterns:
        if re.search(pat, text, re.IGNORECASE):
            violations.append(desc)
            max_risk = max(max_risk, 85.0)

    return max_risk, violations


# 3. Pydantic Input and Output envelopes
class LeakBusterInput(BaseModel):
    text: str = Field(..., description="The outgoing payload or text draft being audited for data privacy leaks")


class LeakBusterOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates whether the payload is safe to send/publish under strict-mode")
    risk_score: float = Field(..., description="The calculated data leak risk level (0-100)")
    status: str = Field(..., description="Scanner status classification (PASSED, WARN_LEAK, REJECTED_LEAK)")
    flagged_leaks: List[str] = Field(default_factory=list, description="List of identified leakage issues")


# 4. Core Micro-Agent Class
class PiPromptLeakBuster:
    """Zero-Trust data privacy egress micro-agent leak scanner."""

    def __init__(self) -> None:
        self.agent_name = "PiPromptLeakBuster"

    def scan_text(self, input_envelope: LeakBusterInput) -> LeakBusterOutput:
        """Audits outgoing text for hardcoded credentials, PII leakage, and system instructions."""
        risk, violations = detect_leak_anomalies(input_envelope.text)

        is_strict = is_strict_mode()
        is_secure = True
        status = "PASSED"

        if risk >= 80.0:
            if is_strict:
                is_secure = False
                status = "REJECTED_LEAK"
            else:
                status = "WARN_LEAK"
        elif risk >= 70.0:
            status = "WARN_LEAK"

        return LeakBusterOutput(is_secure=is_secure, risk_score=risk, status=status, flagged_leaks=violations)
