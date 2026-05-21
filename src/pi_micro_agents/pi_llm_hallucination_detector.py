from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_HALLUCINATION_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_HALLUCINATION_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class HallucinationDetectorInput(BaseModel):
    prompt: str = Field(..., description="The user prompt or context sent to LLM")
    response: str = Field(..., description="The generated response text from LLM")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class HallucinationDetectorOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if LLM output is free from logical contradictions")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable segments or sentences in text")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed logical contradictions or hallucination findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_HALLUCINATION, REJECTED_HALLUCINATION)")


# 3. Core Micro-Agent Class
class PiLLMHallucinationDetector:
    """Specialized AI safety micro-agent that audits LLM outputs for self-contradictions and logical drift in high-risk factual domains."""

    def __init__(self) -> None:
        self.agent_name = "PiLLMHallucinationDetector"

    def audit_hallucination(self, input_envelope: HallucinationDetectorInput) -> HallucinationDetectorOutput:
        """Autonomously audits LLM outputs for self-contradiction patterns and semantic factuality drift."""
        text = input_envelope.response
        vulnerable_funcs = []
        flagged_findings = []

        # Find direct self-contradictions
        # Case 1: Statement declaring a state is secure, and then later declaring it is insecure in same text
        secure_stmt = re.search(r'\b(is\s+secure|no\s+vulnerabilities|passed|clean)\b', text, re.IGNORECASE)
        insecure_stmt = re.search(r'\b(is\s+vulnerable|has\s+exploits|rejected|danger|unsafe)\b', text, re.IGNORECASE)

        if secure_stmt and insecure_stmt:
            vulnerable_funcs.append("response_text")
            flagged_findings.append(
                "LLM response contains conflicting claims: it asserts both security clearance ('secure', 'passed') "
                "and vulnerability risks ('vulnerable', 'unsafe') inside the same response envelope. "
                "This indicates potential semantic hallucination and logical self-contradiction."
            )

        # Case 2: Claiming full compliance, but listing failures
        compliance_passed = re.search(r'\b(fully\s+compliant|100%\s+coverage)\b', text, re.IGNORECASE)
        failed_checks = re.search(r'\b(failed|violations\s+found|non-compliant)\b', text, re.IGNORECASE)

        if compliance_passed and failed_checks:
            vulnerable_funcs.append("response_text")
            flagged_findings.append(
                "LLM response asserts complete spec compliance while listing explicit validation failures. "
                "This represents logical hallucination and structural mismatch."
            )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_HALLUCINATION"
            else:
                status = "WARN_HALLUCINATION"
                is_secure = True

        return HallucinationDetectorOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
