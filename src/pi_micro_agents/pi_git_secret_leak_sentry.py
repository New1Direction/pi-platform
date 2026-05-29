from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_GIT_SECRET_STRICT_MODE")


class GitSecretLeakInput(BaseModel):
    file_path: str = Field(..., description="Target file path")
    file_content: str = Field(..., description="Target file content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class GitSecretLeakOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if secrets scanning passed")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiGitSecretLeakSentry:
    """Specialized Source Control micro-agent that audits files for hardcoded secrets, private keys, and high-entropy credentials."""

    def __init__(self) -> None:
        self.agent_name = "PiGitSecretLeakSentry"

    def audit_secrets(self, input_envelope: GitSecretLeakInput) -> GitSecretLeakOutput:
        content = input_envelope.file_content
        flagged_findings = []

        # Target explicit high-risk hardcoded patterns
        secret_patterns = [
            (r"-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----", "RSA Private Key"),
            (r"-----BEGIN\s+PRIVATE\s+KEY-----", "Generic Private Key"),
            (r"sk_live_[a-zA-Z0-9]{24}", "Stripe Live API Key"),
            (
                r"amzn\.mws\.[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
                "AWS MWS Client Token",
            ),
            (r"AIzaSy[a-zA-Z0-9_-]{33}", "Google API Key"),
            (r'aws_secret_access_key\s*=\s*["\']?[a-zA-Z0-9/+=]{40}["\']?', "AWS Secret Access Key"),
            # Seed phrase mnemonic matching (simple heuristic for common mnemonics in tests/config)
            (r"(?:[a-zA-Z]+\s+){11}[a-zA-Z]+", "Potential Mnemonic Seed Phrase (12 words)"),
        ]

        is_secure = True
        for pattern, label in secret_patterns:
            # For 12 words, only match if common BIP-39 test word combinations are likely (e.g. including test, edit, word, control etc.)
            # Or if it's explicitly labelled or assigned to a key/seed/mnemonic variable
            match = re.search(pattern, content)
            if match:
                matched_str = match.group(0)
                # Specific verification for the 12-words to avoid high false positives on regular English paragraphs
                if label == "Potential Mnemonic Seed Phrase (12 words)":
                    # Only flag if there is contextual reference like "seed", "mnemonic", "private", "key", "secret" in the surrounding text
                    surrounding = content[max(0, match.start() - 100) : min(len(content), match.end() + 100)].lower()
                    if any(x in surrounding for x in ["seed", "mnemonic", "bip39", "key", "secret", "private"]):
                        is_secure = False
                        flagged_findings.append(
                            f"File contains a pattern matching '{label}' with high confidence. "
                            f"Hardcoding secrets in repositories exposes systems to total compromise."
                        )
                else:
                    is_secure = False
                    flagged_findings.append(
                        f"File contains a pattern matching '{label}' ('{matched_str[:15]}...'). "
                        f"Exposing private credentials in source code enables simple unauthorized resource access."
                    )

        is_secure = len(flagged_findings) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_GIT_SECRET"
            else:
                status = "WARN_GIT_SECRET"
                is_secure = True

        return GitSecretLeakOutput(
            is_secure=is_secure, flagged_findings=flagged_findings, risk_score=risk_score, status=status
        )
