from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_MOBILE_SECURITY_STRICT_MODE")


# MASVS-STORAGE: Insecure storage patterns
_INSECURE_STORAGE_ANDROID = re.compile(
    r"\b(?:SharedPreferences|getSharedPreferences|PreferenceManager\.getDefaultSharedPreferences)\b",
    re.IGNORECASE,
)
_INSECURE_STORAGE_IOS = re.compile(
    r"\bNSUserDefaults\b",
    re.IGNORECASE,
)
_INSECURE_STORAGE_RN = re.compile(
    r"\bAsyncStorage\b",
    re.IGNORECASE,
)
_INSECURE_STORAGE_FLUTTER = re.compile(
    r"\bshared_preferences\b",
    re.IGNORECASE,
)
_SECURE_STORAGE_MARKERS = re.compile(
    r"\b(?:EncryptedSharedPreferences|KeyStore|SecretKey|KeychainSwift|SecItemAdd|"
    r"flutter_secure_storage|react-native-keychain|react_native_keychain|Keychain\.set)\b",
    re.IGNORECASE,
)

# MASVS-CRYPTO: Hardcoded secrets / weak crypto
_HARDCODED_KEY = re.compile(
    r"""(?:api[_-]?key|secret|password|token|private[_-]?key)\s*[=:]\s*['"][^'"]{8,}['"]""",
    re.IGNORECASE,
)
_WEAK_CRYPTO = re.compile(r"\b(?:MD5|SHA1|SHA-1|DES\b|3DES|RC4|ECB)\b", re.IGNORECASE)

# MASVS-NETWORK: Certificate pinning disabled / cleartext allowed
_PINNING_DISABLED = re.compile(
    r"\b(?:TrustAllCerts|X509TrustManager|trustManager\s*=\s*null|"
    r"setHostnameVerifier\s*\(\s*SSLSocketFactory\.ALLOW_ALL_HOSTNAME_VERIFIER\s*\)|"
    r"allowsInvalidCertificates\s*=\s*true|"
    r"validatesDomainName\s*=\s*false)\b",
    re.IGNORECASE,
)
_CLEARTEXT_TRAFFIC = re.compile(
    r"""(?:usesCleartextTraffic\s*=\s*["']?true["']?|"""
    r"""android:usesCleartextTraffic\s*=\s*["']true["']|"""
    r"""NSAllowsArbitraryLoads\s*[=<>:,\s]*(?:true|YES|1)|"""
    r"""['"](http://)[^'"]{5,}['"])""",
    re.IGNORECASE,
)
# plist-style: <key>NSAllowsArbitraryLoads</key> ... <true/>
_PLIST_ARBITRARY_LOADS = re.compile(
    r"NSAllowsArbitraryLoads.{0,80}<true\s*/?>",
    re.IGNORECASE | re.DOTALL,
)

# MASVS-PLATFORM: WebView JS + deeplink injection
_WEBVIEW_JS_ENABLED = re.compile(
    r"\b(?:setJavaScriptEnabled\s*\(\s*true\s*\)|WKPreferences\.javaScriptEnabled\s*=\s*true)\b",
    re.IGNORECASE,
)
_WEBVIEW_UNIVERSAL_LINKS = re.compile(
    r"\b(?:shouldOverrideUrlLoading|openURL|url\.startsWith)\b.*http",
    re.IGNORECASE,
)
_DEEPLINK_NO_VALIDATION = re.compile(
    r"\b(?:intent\.getData|getIntent\(\)\.getDataString|handleDeepLink|onNewIntent)\b",
    re.IGNORECASE,
)

# MASVS-AUTH: Biometric bypasses
_BIOMETRIC_BYPASS = re.compile(
    r"\b(?:setDeviceCredentialAllowed\s*\(\s*true\s*\)|"
    r"BiometricManager\.Authenticators\.DEVICE_CREDENTIAL|"
    r"LAPolicy\.deviceOwnerAuthentication\b)\b",
    re.IGNORECASE,
)

# MASVS-RESILIENCE: Jailbreak/root detection disabled
_JAILBREAK_DETECT_DISABLED = re.compile(
    r"\b(?:isJailbroken\s*=\s*false|isRooted\s*=\s*false|"
    r"RootBeer\.isRooted\(\)\s*==\s*false|DTTJailbreakDetection\.isJailbroken\(\)\s*==\s*false)\b",
    re.IGNORECASE,
)

# Log/debug exposure
_LOG_SENSITIVE = re.compile(
    r"\b(?:Log\.[dviwe]|NSLog|print\s*\(|console\.log)\b",
    re.IGNORECASE,
)

_PLATFORM_ALIASES = {
    "ios": ["swift", "objc", "objective-c"],
    "android": ["kotlin", "java"],
    "flutter": ["dart", "flutter"],
    "react_native": ["react-native", "reactnative", "rn"],
}


class MobileAuditInput(BaseModel):
    code_content: str = Field(..., description="Source code content to audit")
    file_path: str = Field(default="", description="File path for context (helps infer platform)")
    platform: str = Field(
        default="unknown",
        description="Mobile platform: ios, android, flutter, react_native, unknown",
    )


class MobileAuditOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no MASVS violations found")
    masvs_violations: List[str] = Field(
        default_factory=list, description="OWASP MASVS violation descriptions with control references"
    )
    risk_score: float = Field(..., description="Mobile security risk score 0-100")
    status: str = Field(..., description="PASSED | WARN_MASVS_RISK | REJECTED_MASVS_VIOLATION")


class PiMobileSecurityAuditor:
    """Static analysis of mobile code against OWASP MASVS/MASTG: storage, crypto, network, platform, auth, resilience."""

    def __init__(self) -> None:
        self.agent_name = "PiMobileSecurityAuditor"

    def _infer_platform(self, file_path: str, platform: str) -> str:
        if platform != "unknown":
            return platform.lower()
        fp = file_path.lower()
        if any(ext in fp for ext in [".swift", ".m", ".storyboard", ".xib", "ios/"]):
            return "ios"
        if any(ext in fp for ext in [".kt", ".java", "android/", "androidmanifest"]):
            return "android"
        if fp.endswith(".dart") or "flutter" in fp:
            return "flutter"
        if "react-native" in fp or "reactnative" in fp or fp.endswith(".tsx") or fp.endswith(".jsx"):
            return "react_native"
        return "unknown"

    def audit_mobile_security(self, input_envelope: MobileAuditInput) -> MobileAuditOutput:
        content = input_envelope.code_content
        content_lower = content.lower()
        violations: list[str] = []
        risk_score = 0.0

        _platform = self._infer_platform(input_envelope.file_path, input_envelope.platform)

        # MASVS-STORAGE-1: Sensitive data in unencrypted storage
        has_secure_storage = bool(_SECURE_STORAGE_MARKERS.search(content))
        insecure_storage_hit = (
            _INSECURE_STORAGE_ANDROID.search(content)
            or _INSECURE_STORAGE_IOS.search(content)
            or _INSECURE_STORAGE_RN.search(content)
            or _INSECURE_STORAGE_FLUTTER.search(content)
        )
        if insecure_storage_hit and not has_secure_storage:
            violations.append(
                "MASVS-STORAGE-1: Sensitive data written to unencrypted storage "
                "(SharedPreferences/NSUserDefaults/AsyncStorage). "
                "Use EncryptedSharedPreferences, iOS Keychain, or flutter_secure_storage."
            )
            risk_score = max(risk_score, 75.0)

        # MASVS-CRYPTO-1: Hardcoded secrets
        if _HARDCODED_KEY.search(content):
            violations.append(
                "MASVS-CRYPTO-1: Hardcoded API key, secret, or credential detected in source. "
                "Secrets must not be embedded in app bundles — use server-side issuance or secure enclaves."
            )
            risk_score = max(risk_score, 90.0)

        # MASVS-CRYPTO-2: Weak cryptographic algorithms
        if _WEAK_CRYPTO.search(content):
            violations.append(
                "MASVS-CRYPTO-2: Weak/deprecated algorithm (MD5, SHA-1, DES, RC4, or ECB mode) detected. "
                "Use AES-GCM, ChaCha20-Poly1305, or SHA-256+."
            )
            risk_score = max(risk_score, 80.0)

        # MASVS-NETWORK-1: Certificate validation disabled
        if _PINNING_DISABLED.search(content):
            violations.append(
                "MASVS-NETWORK-1: Certificate validation or hostname verification disabled. "
                "This allows MITM attacks. Remove TrustAllCerts / allowsInvalidCertificates patterns."
            )
            risk_score = max(risk_score, 95.0)

        # MASVS-NETWORK-2: Cleartext HTTP traffic allowed
        if _CLEARTEXT_TRAFFIC.search(content) or _PLIST_ARBITRARY_LOADS.search(content):
            violations.append(
                "MASVS-NETWORK-2: Cleartext HTTP traffic permitted "
                "(usesCleartextTraffic=true or NSAllowsArbitraryLoads). "
                "All app traffic must use TLS 1.2+ with valid certificates."
            )
            risk_score = max(risk_score, 85.0)

        # MASVS-PLATFORM-1: WebView JavaScript enabled
        if _WEBVIEW_JS_ENABLED.search(content):
            violations.append(
                "MASVS-PLATFORM-1: WebView JavaScript enabled. "
                "Only enable for trusted content with strict CSP. "
                "Disable addJavascriptInterface for untrusted origins."
            )
            risk_score = max(risk_score, 65.0)

        # MASVS-PLATFORM-2: Deeplink without validation
        if _DEEPLINK_NO_VALIDATION.search(content):
            has_validation = "validate" in content_lower or "whitelist" in content_lower or "allowlist" in content_lower
            if not has_validation:
                violations.append(
                    "MASVS-PLATFORM-2: Deeplink/intent handler detected without apparent URL validation. "
                    "Validate all incoming deeplink parameters against an allowlist before processing."
                )
                risk_score = max(risk_score, 70.0)

        # MASVS-AUTH-2: Biometric auth allowing device credential fallback
        if _BIOMETRIC_BYPASS.search(content):
            violations.append(
                "MASVS-AUTH-2: Biometric authentication configured to fall back to device PIN/password. "
                "For sensitive operations require strong biometrics only (Class 3 / Face ID with no fallback)."
            )
            risk_score = max(risk_score, 55.0)

        # MASVS-RESILIENCE-1: Jailbreak detection hardcoded disabled
        if _JAILBREAK_DETECT_DISABLED.search(content):
            violations.append(
                "MASVS-RESILIENCE-1: Jailbreak/root detection appears hardcoded to false. "
                "Remove static bypasses; use runtime integrity checks."
            )
            risk_score = max(risk_score, 60.0)

        # Log/debug output — warn only in non-debug contexts
        if _LOG_SENSITIVE.search(content) and (
            "password" in content_lower
            or "token" in content_lower
            or "secret" in content_lower
            or "ssn" in content_lower
        ):
            violations.append(
                "MASVS-STORAGE-2: Sensitive data (password/token/secret) appears alongside debug log calls. "
                "Scrub sensitive fields before logging; strip all debug logs from production builds."
            )
            risk_score = max(risk_score, 70.0)

        is_secure = len(violations) == 0
        strict = is_strict_mode()

        if violations:
            if strict:
                status = "REJECTED_MASVS_VIOLATION"
                is_secure = False
            else:
                status = "WARN_MASVS_RISK"
                is_secure = True
        else:
            status = "PASSED"

        return MobileAuditOutput(
            is_secure=is_secure,
            masvs_violations=violations,
            risk_score=round(risk_score, 1),
            status=status,
        )
