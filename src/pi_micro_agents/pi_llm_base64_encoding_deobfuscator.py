from __future__ import annotations

import base64
import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_LLM_BASE64_DEOBFUSCATOR_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class LLMBase64DeobfuscatorInput(BaseModel):
    prompt: str = Field(..., description="The user prompt string to audit")
    check_level: str = Field(default="STRICT", description="Strictness level")


class LLMBase64DeobfuscatorOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if no hidden obfuscated prompts are embedded")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiLLMBase64EncodingDeobfuscator:
    """Specialized AI safety micro-agent that decodes Base64 payloads to inspect for hidden malicious instructions."""

    def __init__(self) -> None:
        self.agent_name = "PiLLMBase64EncodingDeobfuscator"

    def audit_base64_deobfuscation(self, input_envelope: LLMBase64DeobfuscatorInput) -> LLMBase64DeobfuscatorOutput:
        prompt = input_envelope.prompt
        flagged_findings = []
        is_secure = True

        # Find Base64-like substrings (lengths > 12, matching b64 chars)
        b64_matches = re.findall(r'\b([a-zA-Z0-9+/]{12,}={0,2})\b', prompt)

        for match in b64_matches:
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                # Check if decoded payload contains jailbreak or system override phrases
                malicious_keywords = ["jailbreak", "override", "system", "ignore", "dan mode", "rules"]
                flagged_words = [word for word in malicious_keywords if word in decoded.lower()]
                if flagged_words:
                    is_secure = False
                    flagged_findings.append(
                        f"Found obfuscated Base64 string that decodes to: '{decoded[:100]}...', containing flagged keywords: {flagged_words}."
                    )
            except Exception:
                pass

        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_LLM_BASE64_DEOBFUSCATOR"
            else:
                status = "WARN_LLM_BASE64_DEOBFUSCATOR"
                is_secure = True

        return LLMBase64DeobfuscatorOutput(
            is_secure=is_secure,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
