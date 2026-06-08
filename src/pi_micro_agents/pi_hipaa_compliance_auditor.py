from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_HIPAA_COMPLIANCE_STRICT_MODE")


# 18 HIPAA PHI identifiers (45 CFR §164.514(b)(2))
_PHI_PATTERNS: list[tuple[str, str]] = [
    ("name", r"\b(?:patient|user|member|client)[_-]?name\b"),
    ("geographic", r"\b(?:street|address|zip|postal|city|county|state|lat|lng|latitude|longitude)\b"),
    ("date", r"\b(?:birth[_-]?date|dob|admission[_-]?date|discharge[_-]?date|death[_-]?date)\b"),
    ("phone", r"\b(?:phone|fax|telephone|mobile)[_-]?(?:number|num|no)?\b"),
    ("fax", r"\bfax[_-]?(?:number|num|no)?\b"),
    ("email", r"\bemail[_-]?(?:address|addr)?\b"),
    ("ssn", r"\b(?:ssn|social[_-]?security[_-]?(?:number|num|no)?)\b"),
    ("mrn", r"\b(?:mrn|medical[_-]?record[_-]?(?:number|num|no)?|patient[_-]?id)\b"),
    ("health_plan", r"\b(?:health[_-]?plan[_-]?(?:id|number|num)|insurance[_-]?id|member[_-]?id)\b"),
    ("account_number", r"\b(?:account[_-]?(?:number|num|no))\b"),
    ("certificate", r"\b(?:certificate|license)[_-]?(?:number|num|no)\b"),
    ("vehicle_id", r"\b(?:vin|vehicle[_-]?(?:id|number|num))\b"),
    ("device_id", r"\b(?:device[_-]?(?:id|serial|identifier)|serial[_-]?number)\b"),
    ("url", r"\bphoto[_-]?url\b"),
    ("ip_address", r"\bip[_-]?(?:address|addr)\b"),
    ("biometric", r"\b(?:biometric|fingerprint|retina|iris|face[_-]?id)\b"),
    ("full_photo", r"\b(?:profile[_-]?photo|patient[_-]?photo|face[_-]?scan)\b"),
    ("other_unique", r"\b(?:unique[_-]?identifier|uuid|guid)\s+(?:of\s+)?(?:patient|member|user)\b"),
]

_LOG_CALL_PATTERN = re.compile(
    r"\b(?:log|logger|print|console\.log|logging\.|print\(|logger\.(?:info|debug|warn|error|critical))\s*[.(]",
    re.IGNORECASE,
)
_CLEARTEXT_HTTP_PATTERN = re.compile(r"""['"](http://)[^'"]+['"]""", re.IGNORECASE)
_ENCRYPTION_MARKERS = ["encrypt", "aes", "fernet", "chacha20", "kms", "vault", "hsm", "tls", "ssl"]
_BAA_MARKERS = ["baa", "business associate", "business_associate", "covered_entity", "hipaa"]

_INSECURE_STORAGE = re.compile(
    r"\b(?:localStorage|sessionStorage|AsyncStorage|SharedPreferences|NSUserDefaults)\s*[\[.=]",
    re.IGNORECASE,
)


class HipaaAuditInput(BaseModel):
    code_content: str = Field(..., description="Source code or config content to audit")
    file_path: str = Field(default="", description="File path for context")
    component_type: str = Field(
        default="unknown",
        description="Component type: logging, api, db, storage, ui, config, unknown",
    )


class HipaaAuditOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no HIPAA PHI exposure risks found")
    phi_identifiers_found: List[str] = Field(
        default_factory=list, description="PHI identifier categories detected in code"
    )
    violations: List[str] = Field(default_factory=list, description="Specific HIPAA violation descriptions")
    risk_score: float = Field(..., description="HIPAA risk score 0-100 (higher = more violations)")
    status: str = Field(..., description="PASSED | WARN_PHI_EXPOSURE | REJECTED_PHI_EXPOSURE")


class PiHipaaComplianceAuditor:
    """Scans code for HIPAA PHI identifier exposure, cleartext transmission, and insecure storage patterns."""

    def __init__(self) -> None:
        self.agent_name = "PiHipaaComplianceAuditor"

    def audit_hipaa_compliance(self, input_envelope: HipaaAuditInput) -> HipaaAuditOutput:
        content = input_envelope.code_content
        content_lower = content.lower()
        violations: list[str] = []
        phi_found: list[str] = []
        risk_score = 0.0

        has_log_calls = bool(_LOG_CALL_PATTERN.search(content))

        for phi_name, pattern in _PHI_PATTERNS:
            if re.search(pattern, content_lower):
                phi_found.append(phi_name)
                if has_log_calls:
                    violations.append(
                        f"PHI field '{phi_name}' appears in file containing log/print calls — "
                        "potential PHI logging violation (HIPAA §164.312(b))"
                    )
                    risk_score = max(risk_score, 85.0)
                else:
                    risk_score = max(risk_score, 40.0)

        if _CLEARTEXT_HTTP_PATTERN.search(content):
            violations.append(
                "Cleartext HTTP URL detected — ePHI must be encrypted in transit (HIPAA §164.312(e)(1))"
            )
            risk_score = max(risk_score, 90.0)

        component = input_envelope.component_type.lower()
        if component in ("db", "storage") and phi_found:
            has_encryption = any(m in content_lower for m in _ENCRYPTION_MARKERS)
            if not has_encryption:
                violations.append(
                    "PHI fields in storage component with no encryption markers detected "
                    "(HIPAA §164.312(a)(2)(iv) — encryption at rest required)"
                )
                risk_score = max(risk_score, 80.0)

        if component == "api" and phi_found:
            if "minimum_necessary" not in content_lower and "minimum necessary" not in content_lower:
                violations.append(
                    "API component exposes PHI fields with no minimum-necessary scoping evident "
                    "(HIPAA §164.502(b) — minimum necessary standard)"
                )
                risk_score = max(risk_score, 55.0)

        if _INSECURE_STORAGE.search(content) and phi_found:
            violations.append(
                "PHI stored in unencrypted browser/device storage (localStorage, SharedPreferences, NSUserDefaults) "
                "— use encrypted keystore or server-side storage (HIPAA §164.312(a)(2)(iv))"
            )
            risk_score = max(risk_score, 75.0)

        baa_referenced = any(m in content_lower for m in _BAA_MARKERS)
        if phi_found and not baa_referenced and component in ("api", "db", "storage"):
            violations.append(
                "PHI handled in backend component with no BAA (Business Associate Agreement) reference — "
                "ensure downstream services have signed BAAs (HIPAA §164.308(b)(1))"
            )
            risk_score = max(risk_score, 45.0)

        is_secure = len(violations) == 0
        strict = is_strict_mode()

        if violations:
            if strict:
                status = "REJECTED_PHI_EXPOSURE"
                is_secure = False
            else:
                status = "WARN_PHI_EXPOSURE"
                is_secure = True
        else:
            status = "PASSED"

        return HipaaAuditOutput(
            is_secure=is_secure,
            phi_identifiers_found=phi_found,
            violations=violations,
            risk_score=round(risk_score, 1),
            status=status,
        )
