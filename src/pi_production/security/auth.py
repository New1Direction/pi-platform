"""Production Security Layer.

Deterministic, governance-first security controls.
- JWT authentication with deterministic validation
- Request signing (HMAC-SHA256)
- Rate limiting (delegates to storage engine)
- Audit logging (delegates to storage engine)
- Secret management with env-var / file fallback
- TLS configuration helpers

No probabilistic decision-making. No LLM. All checks are deterministic.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import stat
import string
import time
from typing import Any, Dict, Optional

_security_logger = logging.getLogger("pi_production.security")


class SecurityError(Exception):
    """Base security error — deterministic, safe to serialize."""

    pass


class AuthenticationError(SecurityError):
    pass


class AuthorizationError(SecurityError):
    pass


class RateLimitExceededError(SecurityError):
    pass


class SignatureError(SecurityError):
    pass


# ──────────────────────────────
#  JWT (Deterministic Claims)
# ──────────────────────────────


class JWTToken:
    """Deterministic JWT with HMAC-SHA256.

    Simplified implementation — no external jose/crypto deps required.
    Claims are deterministic (no randomness in claim generation).
    """

    ALGORITHM = "HS256"

    def __init__(self, secret: str) -> None:
        self.secret = secret.encode() if isinstance(secret, str) else secret

    def _encode_segment(self, data: Dict[str, Any]) -> str:
        return base64url(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())

    def _sign(self, msg: bytes) -> bytes:
        return hmac.new(self.secret, msg, hashlib.sha256).digest()

    def encode(self, claims: Dict[str, Any], ttl_seconds: int = 3600) -> str:
        header = self._encode_segment({"alg": self.ALGORITHM, "typ": "JWT"})
        now = int(time.time())
        payload = dict(claims)
        payload.update(
            {
                "iat": now,
                "exp": now + ttl_seconds,
                "jti": self._derive_jti(payload),
            }
        )
        body = self._encode_segment(payload)
        sig = base64url(self._sign(f"{header}.{body}".encode()))
        return f"{header}.{body}.{sig}"

    def decode(self, token: str) -> Dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            raise AuthenticationError("invalid_token_format")
        header_b64, body_b64, sig_b64 = parts
        expected_sig = base64url(self._sign(f"{header_b64}.{body_b64}".encode()))
        if not secrets.compare_digest(sig_b64, expected_sig):
            raise AuthenticationError("signature_mismatch")
        payload = json.loads(base64url_decode(body_b64))
        if payload.get("exp", 0) < int(time.time()):
            raise AuthenticationError("token_expired")
        return payload

    def _derive_jti(self, claims: Dict[str, Any]) -> str:
        """Deterministic JTI from claims hash."""
        return hashlib.sha256(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]


def base64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def base64url_decode(s: str) -> bytes:
    import base64

    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


# ──────────────────────────────
#  Request Signing
# ──────────────────────────────


class RequestSigner:
    """HMAC-SHA256 request signing for API protection.

    Signature covers: method, path, timestamp, body hash, tenant_id.
    Prevents replay attacks via timestamp tolerance.
    """

    TIMESTAMP_TOLERANCE_SECONDS = 300

    def __init__(self, secret: str) -> None:
        self.secret = secret.encode()

    def sign(self, method: str, path: str, timestamp: int, tenant_id: str, body: bytes = b"") -> str:
        body_hash = hashlib.sha256(body).hexdigest()
        msg = f"{method}:{path}:{timestamp}:{tenant_id}:{body_hash}"
        return hmac.new(self.secret, msg.encode(), hashlib.sha256).hexdigest()

    def verify(self, signature: str, method: str, path: str, timestamp: int, tenant_id: str, body: bytes = b"") -> None:
        now = int(time.time())
        if abs(now - timestamp) > self.TIMESTAMP_TOLERANCE_SECONDS:
            raise SignatureError("timestamp_outside_tolerance")
        expected = self.sign(method, path, timestamp, tenant_id, body)
        if not secrets.compare_digest(signature, expected):
            raise SignatureError("signature_mismatch")


# ──────────────────────────────
#  Secret Manager
# ──────────────────────────────


class SecretManager:
    """Deterministic secret resolution with fallbacks:
    1. Environment variable
    2. File in specified directory
    3. Fallback placeholder (logs a warning)
    """

    def __init__(self, secrets_dir: Optional[str] = None) -> None:
        self.secrets_dir = secrets_dir

    # On non-Windows systems, refuse to read a secret file unless its mode
    # is owner-readable only (no group/other bits). Enforced strictly by
    # default; set PI_SECRET_PERMISSIVE=1 to downgrade to a warning.
    _STRICT_MODE = os.name != "nt"

    def get(self, name: str, default: Optional[str] = None) -> str:
        env_key = f"PI_SECRET_{name.upper()}"
        if env_key in os.environ:
            return os.environ[env_key]
        if self.secrets_dir:
            path = os.path.join(self.secrets_dir, name.lower())
            if os.path.exists(path):
                if self._STRICT_MODE:
                    self._check_secret_file_mode(path)
                with open(path, "r") as f:
                    return f.read().strip()
        if default is not None:
            return default
        raise SecurityError(f"secret_not_found:{name}")

    @classmethod
    def _check_secret_file_mode(cls, path: str) -> None:
        try:
            st = os.stat(path)
        except OSError as e:
            raise SecurityError(f"secret_stat_failed:{path}:{e}") from e
        mode = st.st_mode & 0o777
        # Group / other bits must be zero — only owner read/write allowed.
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            msg = f"secret_file_too_permissive: {path} mode is {oct(mode)}; expected 0600 (chmod 600 {path})"
            if os.getenv("PI_SECRET_PERMISSIVE") == "1":
                _security_logger.warning(msg)
            else:
                raise SecurityError(msg)

    def rotate_secret(self, name: str, length: int = 64) -> str:
        """Generate a deterministic-looking random secret."""
        alphabet = string.ascii_letters + string.digits + "_-"
        return "".join(secrets.choice(alphabet) for _ in range(length))


# ──────────────────────────────
#  Role-Based Access Control (RBAC)
# ──────────────────────────────


class RBACPolicy:
    """Deterministic RBAC with hardcoded roles and permissions.

    Roles: admin, operator, viewer, api_key
    Permissions map to API action patterns.
    """

    PERMISSIONS = {
        "admin": ["*"],
        "operator": [
            "composition:simulate",
            "composition:submit",
            "snapshot:list",
            "snapshot:get",
            "snapshot:store",
            "replay:view",
            "replay:diff",
            "audit:read",
            "audit:query",
            "metrics:read",
            "health:read",
        ],
        "viewer": [
            "snapshot:list",
            "snapshot:get",
            "replay:view",
            "audit:query",
            "metrics:read",
            "health:read",
        ],
        "api_key": [
            "composition:simulate",
            "composition:submit",
            "snapshot:list",
            "snapshot:get",
            "snapshot:store",
        ],
    }

    def allowed(self, role: str, action: str) -> bool:
        perms = self.PERMISSIONS.get(role, [])
        return "*" in perms or action in perms

    def allowed_tenants(self, role: str, requested_tenant: str, token_tenant: str) -> bool:
        """Cross-tenant access only allowed for admin."""
        if role == "admin":
            return True
        return requested_tenant == token_tenant


# ──────────────────────────────
#  Request Context
# ──────────────────────────────


class SecurityContext:
    """Immutable context attached to every production request."""

    def __init__(
        self,
        tenant_id: str,
        actor_id: str,
        role: str,
        correlation_id: str,
        jwt_claims: Optional[Dict[str, Any]] = None,
        request_signature: Optional[str] = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.actor_id = actor_id
        self.role = role
        self.correlation_id = correlation_id
        self.jwt_claims = jwt_claims or {}
        self.request_signature = request_signature

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "actor_id": self.actor_id,
            "role": self.role,
            "correlation_id": self.correlation_id,
            "request_signature_present": self.request_signature is not None,
        }
