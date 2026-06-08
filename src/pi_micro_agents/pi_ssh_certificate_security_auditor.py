from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_SSH_CERT_SECURITY_STRICT_MODE")


# --- Expiry validation gap ---
# sshcerts parses valid_after/valid_before but leaves enforcement to callers.
# Detect: cert is parsed but neither field is checked.
_CERT_PARSE = re.compile(
    r"\b(?:Certificate::from_string|Certificate::from_bytes|Certificate::from_path|"
    r"ssh\.ParseCertificate|paramiko.*Certificate|cert_from_string|parse_certificate)\s*[(\[]",
    re.IGNORECASE,
)
_EXPIRY_CHECK = re.compile(
    r"\b(?:valid_before|valid_after|not_after|not_before|expires_at|expiry|"
    r"cert\.validity|ValidBefore|ValidAfter|NotAfter|NotBefore)\b",
    re.IGNORECASE,
)

# --- Principal validation gap ---
# Certificates carry a `principals` list; callers must verify the list contains the expected identity.
_PRINCIPAL_CHECK = re.compile(
    r"\b(?:principals|valid_principals|certPrincipals|cert\.principals|"
    r"check_principal|validate_principal|authorized_principals)\b",
    re.IGNORECASE,
)

# --- Weak RSA signing (SHA-1) ---
_WEAK_RSA_SHA1 = re.compile(
    r"\b(?:rsa-sha|ssh-rsa\b|RSA_SHA1|rsa_v1_5_sha1|sha1WithRSA|"
    r"SignatureAlgorithm::RSA_PKCS1_SHA1|rsa_pkcs1_sha1)\b",
    re.IGNORECASE,
)

# --- Critical options not validated ---
# force-command and source-address in cert critical_options restrict usage.
# Callers should at minimum log or check critical_options before trusting a cert.
_CRITICAL_OPTIONS_CHECK = re.compile(
    r"\b(?:critical_options|criticalOptions|force.command|source.address|"
    r"cert\.extensions|cert\.critical)\b",
    re.IGNORECASE,
)

# --- No revocation / CRL / OCSP checking ---
_REVOCATION_CHECK = re.compile(
    r"\b(?:revoke|revocation|CRL|OCSP|revoked_certs|cert_revocation|"
    r"KnownRevoked|revocation_list)\b",
    re.IGNORECASE,
)

# --- Plaintext webhook secrets in config/code ---
# Sourced from obelisk/plaid pattern: ResponseMode::Facebook("secret") stored as String
_PLAINTEXT_WEBHOOK_SECRET = re.compile(
    r"""(?:webhook[_-]?secret|facebook[_-]?secret|hmac[_-]?secret|signing[_-]?secret)\s*"""
    r"""[:=]\s*['"][^'"]{8,}['"]""",
    re.IGNORECASE,
)

# --- Module signing without CA expiry check ---
# Pattern from plaid: authorized signer fingerprints checked but CA cert expiry not validated
_SIGNER_FINGERPRINT_NO_EXPIRY = re.compile(
    r"\b(?:authorized_signers|allowed_signers|signer_fingerprint|verify_signature)\b",
    re.IGNORECASE,
)

# --- Token stored without zeroization ---
_TOKEN_NO_ZEROIZE = re.compile(
    r"\b(?:auth_token|api_token|access_token|private_key|secret_key)\s*:\s*String\b",
    re.IGNORECASE,
)
_ZEROIZE_PRESENT = re.compile(
    r"\b(?:Zeroize|zeroize|ZeroizeOnDrop|SecretBox|secrecy::Secret|"
    r"zeroize_on_drop|sensitive_data)\b",
    re.IGNORECASE,
)

# --- Cert type not checked (user vs host cert) ---
_CERT_TYPE_CHECK = re.compile(
    r"\b(?:cert_type|CertType|UserCert|HostCert|SSH_CERT_TYPE_USER|"
    r"SSH_CERT_TYPE_HOST|is_user_cert|is_host_cert)\b",
    re.IGNORECASE,
)


class SshCertInput(BaseModel):
    code_content: str = Field(..., description="Source code content to audit (Rust, Python, Go, or config)")
    file_path: str = Field(default="", description="File path for context")
    has_cert_parsing: bool = Field(
        default=False,
        description="Set True if caller knows this file does SSH cert parsing (helps suppress false positives)",
    )


class SshCertOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no SSH certificate security gaps found")
    gaps: List[str] = Field(default_factory=list, description="Security gap descriptions")
    risk_score: float = Field(..., description="SSH certificate security risk score 0-100")
    status: str = Field(..., description="PASSED | WARN_CERT_GAP | REJECTED_CERT_GAP")


class PiSshCertificateSecurityAuditor:
    """
    Audits code for SSH certificate security gaps: missing expiry validation, no principal
    check, weak SHA-1 RSA, no revocation, plaintext webhook secrets, and token zeroization.

    Patterns sourced from RE of obelisk/sshcerts and obelisk/plaid.
    The sshcerts library explicitly leaves expiry and principal validation to callers —
    this agent detects callsites that omit these required checks.
    """

    def __init__(self) -> None:
        self.agent_name = "PiSshCertificateSecurityAuditor"

    def audit_ssh_cert_security(self, input_envelope: SshCertInput) -> SshCertOutput:
        content = input_envelope.code_content
        gaps: list[str] = []
        risk_score = 0.0

        has_cert_parse = input_envelope.has_cert_parsing or bool(_CERT_PARSE.search(content))

        if has_cert_parse:
            # Expiry validation
            if not _EXPIRY_CHECK.search(content):
                gaps.append(
                    "SSH certificate parsed but valid_before/valid_after never checked — "
                    "sshcerts deliberately leaves expiry enforcement to callers. "
                    "Add: assert!(cert.valid_before > current_unix_time)"
                )
                risk_score = max(risk_score, 80.0)

            # Principal validation
            if not _PRINCIPAL_CHECK.search(content):
                gaps.append(
                    "SSH certificate parsed but principals list not validated — "
                    "any identity in principals will be accepted without verification. "
                    "Verify cert.principals.contains(&expected_principal) before trusting."
                )
                risk_score = max(risk_score, 75.0)

            # Cert type not checked
            if not _CERT_TYPE_CHECK.search(content):
                gaps.append(
                    "SSH certificate type (user vs host) not checked — "
                    "a host certificate should not be accepted for user authentication and vice versa. "
                    "Check cert.cert_type == CertType::User or CertType::Host explicitly."
                )
                risk_score = max(risk_score, 65.0)

            # Critical options not inspected
            if not _CRITICAL_OPTIONS_CHECK.search(content):
                gaps.append(
                    "SSH certificate critical_options not inspected — "
                    "force-command and source-address restrictions in the cert will be silently ignored "
                    "if the caller does not read and enforce them."
                )
                risk_score = max(risk_score, 55.0)

            # Revocation
            if not _REVOCATION_CHECK.search(content):
                gaps.append(
                    "No certificate revocation check (CRL/OCSP/revocation list) detected — "
                    "sshcerts has no built-in revocation; callers must implement their own revoked-cert list."
                )
                risk_score = max(risk_score, 50.0)

        # Weak RSA SHA-1 — applies regardless of parse context
        if _WEAK_RSA_SHA1.search(content):
            gaps.append(
                "ssh-rsa / SHA-1 RSA signature algorithm detected — "
                "deprecated since OpenSSH 8.8 (2021). Use rsa-sha2-256 or rsa-sha2-512. "
                "Clients still negotiating ssh-rsa are vulnerable to SHA-1 chosen-prefix attacks."
            )
            risk_score = max(risk_score, 70.0)

        # Plaintext webhook secrets
        if _PLAINTEXT_WEBHOOK_SECRET.search(content):
            gaps.append(
                "Plaintext webhook signing secret embedded in code/config — "
                "store in environment variable or secret manager; "
                "obelisk/plaid pattern: ResponseMode::Facebook(secret_string) stores secret as plain String."
            )
            risk_score = max(risk_score, 75.0)

        # Module signer fingerprint check without CA expiry
        if _SIGNER_FINGERPRINT_NO_EXPIRY.search(content) and not _EXPIRY_CHECK.search(content):
            gaps.append(
                "Module signing via authorized signer fingerprints without CA certificate expiry validation — "
                "the CA cert used to sign module-signing keys may itself be expired (obelisk/plaid gap)."
            )
            risk_score = max(risk_score, 55.0)

        # Token stored as plain String without zeroization
        if _TOKEN_NO_ZEROIZE.search(content) and not _ZEROIZE_PRESENT.search(content):
            gaps.append(
                "Auth/API token stored as plain Rust String without Zeroize — "
                "sensitive secrets should use secrecy::Secret<String> or implement ZeroizeOnDrop "
                "to scrub memory on drop."
            )
            risk_score = max(risk_score, 50.0)

        is_secure = len(gaps) == 0
        strict = is_strict_mode()

        if gaps:
            if strict:
                status = "REJECTED_CERT_GAP"
                is_secure = False
            else:
                status = "WARN_CERT_GAP"
                is_secure = True
        else:
            status = "PASSED"

        return SshCertOutput(
            is_secure=is_secure,
            gaps=gaps,
            risk_score=round(risk_score, 1),
            status=status,
        )
