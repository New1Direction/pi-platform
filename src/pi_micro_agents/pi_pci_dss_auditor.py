from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_PCI_DSS_STRICT_MODE")


# PAN (Primary Account Number) patterns — detect card number fields/variables
_PAN_FIELD_PATTERN = re.compile(
    r"\b(?:card[_-]?(?:number|num|no)|pan|primary[_-]?account[_-]?number|cc[_-]?number|credit[_-]?card)\b",
    re.IGNORECASE,
)
# CVV/CVC fields — must NEVER be stored after auth (PCI DSS Req 3.3)
_CVV_FIELD_PATTERN = re.compile(
    r"\b(?:cvv|cvv2|cvc|cvc2|card[_-]?verification|security[_-]?code|card[_-]?security)\b",
    re.IGNORECASE,
)
# Expiry stored in DB columns
_EXPIRY_FIELD_PATTERN = re.compile(
    r"\b(?:expiry|expiration|exp[_-]?(?:date|month|year)|card[_-]?exp)\b",
    re.IGNORECASE,
)
_LOG_CALL_PATTERN = re.compile(
    r"\b(?:log|logger|print|console\.log|logging\.|logger\.(?:info|debug|warn|error|critical))\s*[.(]",
    re.IGNORECASE,
)
_CLEARTEXT_HTTP = re.compile(r"""['"](http://)[^'"]+['"]""", re.IGNORECASE)
_ENCRYPTION_MARKERS = ["encrypt", "aes", "aes-256", "fernet", "chacha20", "vault", "kms", "tokeniz", "p2pe"]
_TOKENIZATION_MARKERS = ["token", "tokenize", "vault_token", "stripe_token", "braintree", "p2pe"]
# Weak auth patterns in payment contexts
_WEAK_AUTH = re.compile(r"\b(?:MD5|SHA1|sha-1|des\b|3des|rc4)\b", re.IGNORECASE)
# TLS version enforcement
_WEAK_TLS = re.compile(r"\b(?:SSLv2|SSLv3|TLS[_ ]?1[_.]0|TLS[_ ]?1[_.]1)\b", re.IGNORECASE)
_PLAINTEXT_STORAGE = re.compile(
    r"\b(?:localStorage|sessionStorage|AsyncStorage|SharedPreferences|NSUserDefaults|cookie)\b",
    re.IGNORECASE,
)

# PCI DSS v4.0 requirement references
_REQ = {
    "pan_log": "Req 3.3.1 — PANs must be masked in logs (first 6/last 4 digits max displayed)",
    "cvv_stored": "Req 3.3.2 — CVV/CVC must never be stored after authorization",
    "cleartext": "Req 4.2.1 — CHD must be encrypted in transit using strong cryptography (TLS 1.2+)",
    "no_encrypt": "Req 3.5.1 — PAN must be stored using strong one-way hashes, truncation, or encryption",
    "weak_crypto": "Req 12.3.3 — Weak/deprecated cryptographic algorithms must not be used (MD5, SHA-1, DES, RC4)",
    "weak_tls": "Req 4.2.1 — TLS 1.0 and 1.1 are prohibited; minimum TLS 1.2 required",
    "browser_storage": "Req 3.3 / 3.5 — CHD must not be stored in browser/unencrypted client storage",
    "expiry_unprotected": "Req 3.3.1 — Card expiry must be protected; store as part of encrypted PAN block",
    "no_tokenization": "Req 3.5 — Consider tokenization or P2PE to minimize CDE scope",
}


class PciDssInput(BaseModel):
    code_content: str = Field(..., description="Source code or config content to audit")
    file_path: str = Field(default="", description="File path for context")
    component_type: str = Field(
        default="unknown",
        description="Component type: payment, api, db, storage, logging, frontend, config, unknown",
    )


class PciDssOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no PCI DSS CHD violations found")
    chd_violations: List[str] = Field(default_factory=list, description="Cardholder Data (CHD) violation descriptions")
    pci_requirements_violated: List[str] = Field(
        default_factory=list, description="PCI DSS v4.0 requirement references violated"
    )
    risk_score: float = Field(..., description="PCI DSS risk score 0-100 (higher = more critical violations)")
    status: str = Field(..., description="PASSED | WARN_CHD_RISK | REJECTED_CHD_VIOLATION")


class PiPciDssAuditor:
    """Scans code for PCI DSS v4.0 cardholder data (CHD) violations including PAN exposure, CVV storage, and weak crypto."""

    def __init__(self) -> None:
        self.agent_name = "PiPciDssAuditor"

    def audit_pci_dss(self, input_envelope: PciDssInput) -> PciDssOutput:
        content = input_envelope.code_content
        content_lower = content.lower()
        violations: list[str] = []
        requirements_violated: list[str] = []
        risk_score = 0.0

        has_pan = bool(_PAN_FIELD_PATTERN.search(content))
        has_cvv = bool(_CVV_FIELD_PATTERN.search(content))
        has_expiry = bool(_EXPIRY_FIELD_PATTERN.search(content))
        has_log_calls = bool(_LOG_CALL_PATTERN.search(content))
        component = input_envelope.component_type.lower()

        # CVV stored anywhere → critical (Req 3.3.2 is absolute)
        if has_cvv:
            if component in ("db", "storage") or re.search(r"\b(?:save|store|insert|persist|write)\b", content_lower):
                violations.append(f"CVV/CVC field detected in a storage/persistence context — {_REQ['cvv_stored']}")
                requirements_violated.append(_REQ["cvv_stored"])
                risk_score = max(risk_score, 100.0)
            elif has_log_calls:
                violations.append(f"CVV/CVC field appears alongside log calls — {_REQ['pan_log']}")
                requirements_violated.append(_REQ["pan_log"])
                risk_score = max(risk_score, 95.0)

        # PAN in log calls
        if has_pan and has_log_calls:
            violations.append(f"PAN field appears alongside log calls — {_REQ['pan_log']}")
            requirements_violated.append(_REQ["pan_log"])
            risk_score = max(risk_score, 90.0)

        # PAN stored without encryption markers
        if has_pan and component in ("db", "storage"):
            has_enc = any(m in content_lower for m in _ENCRYPTION_MARKERS)
            has_tok = any(m in content_lower for m in _TOKENIZATION_MARKERS)
            if not has_enc and not has_tok:
                violations.append(f"PAN stored in DB/storage with no encryption or tokenization — {_REQ['no_encrypt']}")
                requirements_violated.append(_REQ["no_encrypt"])
                risk_score = max(risk_score, 95.0)
            elif not has_tok:
                violations.append(
                    f"PAN stored without tokenization/P2PE — scope reduction opportunity — {_REQ['no_tokenization']}"
                )
                requirements_violated.append(_REQ["no_tokenization"])
                risk_score = max(risk_score, 40.0)

        # Cleartext HTTP carrying CHD
        if _CLEARTEXT_HTTP.search(content) and (has_pan or has_cvv):
            violations.append(f"Cleartext HTTP used in CHD context — {_REQ['cleartext']}")
            requirements_violated.append(_REQ["cleartext"])
            risk_score = max(risk_score, 95.0)

        # Weak crypto algorithms
        if _WEAK_AUTH.search(content):
            violations.append(f"Weak/deprecated cryptographic algorithm — {_REQ['weak_crypto']}")
            requirements_violated.append(_REQ["weak_crypto"])
            risk_score = max(risk_score, 80.0)

        # Weak TLS versions
        if _WEAK_TLS.search(content):
            violations.append(f"Weak TLS version configured — {_REQ['weak_tls']}")
            requirements_violated.append(_REQ["weak_tls"])
            risk_score = max(risk_score, 85.0)

        # CHD in browser/unencrypted client storage
        if _PLAINTEXT_STORAGE.search(content) and (has_pan or has_cvv):
            violations.append(f"CHD in unencrypted client-side storage — {_REQ['browser_storage']}")
            requirements_violated.append(_REQ["browser_storage"])
            risk_score = max(risk_score, 90.0)

        # Expiry without PAN encryption block
        if has_expiry and component in ("db", "storage"):
            has_enc = any(m in content_lower for m in _ENCRYPTION_MARKERS)
            if not has_enc:
                violations.append(f"Card expiry in storage without encryption — {_REQ['expiry_unprotected']}")
                requirements_violated.append(_REQ["expiry_unprotected"])
                risk_score = max(risk_score, 60.0)

        is_secure = len(violations) == 0
        strict = is_strict_mode()

        if violations:
            if strict:
                status = "REJECTED_CHD_VIOLATION"
                is_secure = False
            else:
                status = "WARN_CHD_RISK"
                is_secure = True
        else:
            status = "PASSED"

        return PciDssOutput(
            is_secure=is_secure,
            chd_violations=violations,
            pci_requirements_violated=list(dict.fromkeys(requirements_violated)),
            risk_score=round(risk_score, 1),
            status=status,
        )
