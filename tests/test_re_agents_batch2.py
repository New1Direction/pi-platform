from __future__ import annotations

from pi_micro_agents.pi_bot_detection_evasion_sentry import BotEvasionInput, PiBotDetectionEvasionSentry
from pi_micro_agents.pi_ssh_certificate_security_auditor import PiSshCertificateSecurityAuditor, SshCertInput

# ---------------------------------------------------------------------------
# PiBotDetectionEvasionSentry
# ---------------------------------------------------------------------------


class TestPiBotDetectionEvasionSentry:
    def setup_method(self) -> None:
        self.agent = PiBotDetectionEvasionSentry()

    def test_passes_clean_code(self) -> None:
        result = self.agent.audit_bot_evasion(
            BotEvasionInput(code_content="def fetch_page(url: str) -> str: return requests.get(url).text")
        )
        assert result.status == "PASSED"
        assert result.is_secure is True
        assert result.risk_score == 0.0

    def test_flags_gpu_pool(self) -> None:
        code = """
webgl_vendor = random.choice(["NVIDIA Corporation", "Intel Inc.", "Apple Inc."])
webgl_renderer = random.choice(gpu_pool)
"""
        result = self.agent.audit_bot_evasion(BotEvasionInput(code_content=code))
        assert result.status in ("WARN_EVASION_PATTERN", "REJECTED_EVASION_PATTERN")
        assert "canvas_fingerprint_synthesis" in result.evasion_techniques
        assert result.risk_score >= 80.0

    def test_flags_static_aes_key(self) -> None:
        code = 'key = bytes.fromhex("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")'
        result = self.agent.audit_bot_evasion(BotEvasionInput(code_content=code))
        assert "static_waf_token_key" in result.evasion_techniques
        assert result.risk_score >= 90.0

    def test_flags_artificial_timing(self) -> None:
        code = """
fp_time = random.uniform(0.5, 3.0)
browser_time = random.uniform(2.0, 8.0)
capabilities_time = random.uniform(1.0, 4.0)
"""
        result = self.agent.audit_bot_evasion(BotEvasionInput(code_content=code))
        assert "artificial_timing_metrics" in result.evasion_techniques
        assert result.risk_score >= 70.0

    def test_flags_tls_spoofing(self) -> None:
        code = """
spec = utls.HelloChrome_Auto
options := []utls.TLSExtension{&utls.RandomTLSExtensionOrder{}}
"""
        result = self.agent.audit_bot_evasion(BotEvasionInput(code_content=code))
        assert "tls_fingerprint_spoofing" in result.evasion_techniques
        assert result.risk_score >= 85.0

    def test_flags_pow_solver(self) -> None:
        code = """
def solve_challenge(target_zeros: int, data: bytes) -> str:
    nonce = 0
    while True:
        attempt = hashlib.sha256(data + str(nonce).encode()).hexdigest()
        if attempt.startswith("0" * target_zeros):
            return attempt
        nonce += 1
"""
        result = self.agent.audit_bot_evasion(BotEvasionInput(code_content=code))
        assert "proof_of_work_solver" in result.evasion_techniques
        assert result.risk_score >= 85.0

    def test_flags_header_order_spoofing(self) -> None:
        code = """
req.Header[fakeheader.OrderKey] = []string{
    "user-agent", "accept", "accept-language", "accept-encoding",
}
"""
        result = self.agent.audit_bot_evasion(BotEvasionInput(code_content=code))
        assert "header_order_spoofing" in result.evasion_techniques

    def test_multiple_techniques_accumulate_risk(self) -> None:
        code = """
webgl_vendor = random.choice(gpu_pool)
key = bytes.fromhex("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2")
fp_time = random.uniform(0.5, 3.0)
"""
        result = self.agent.audit_bot_evasion(BotEvasionInput(code_content=code))
        assert len(result.evasion_techniques) >= 2
        assert result.risk_score >= 90.0

    def test_agent_name(self) -> None:
        assert self.agent.agent_name == "PiBotDetectionEvasionSentry"


# ---------------------------------------------------------------------------
# PiSshCertificateSecurityAuditor
# ---------------------------------------------------------------------------


class TestPiSshCertificateSecurityAuditor:
    def setup_method(self) -> None:
        self.agent = PiSshCertificateSecurityAuditor()

    def test_passes_clean_code(self) -> None:
        result = self.agent.audit_ssh_cert_security(
            SshCertInput(code_content="fn greet() { println!(\"hello\"); }")
        )
        assert result.status == "PASSED"
        assert result.is_secure is True
        assert result.risk_score == 0.0

    def test_flags_cert_parse_without_expiry(self) -> None:
        code = """
let cert = Certificate::from_string(&cert_str).unwrap();
if cert.principals.contains(&username) {
    authorize();
}
"""
        result = self.agent.audit_ssh_cert_security(SshCertInput(code_content=code))
        assert result.status in ("WARN_CERT_GAP", "REJECTED_CERT_GAP")
        assert any("never checked" in g or "valid_before" in g for g in result.gaps)
        assert result.risk_score >= 65.0

    def test_passes_cert_with_expiry_and_principal(self) -> None:
        code = """
let cert = Certificate::from_string(&cert_str).unwrap();
let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
assert!(cert.valid_before > now, "Certificate expired");
assert!(cert.valid_after < now, "Certificate not yet valid");
assert!(cert.principals.contains(&expected_principal));
assert_eq!(cert.cert_type, CertType::User);
"""
        result = self.agent.audit_ssh_cert_security(SshCertInput(code_content=code))
        # Should pass or have only minor gaps
        assert result.risk_score < 70.0

    def test_flags_weak_rsa_sha1(self) -> None:
        code = 'algorithm = "ssh-rsa"  # deprecated, use rsa-sha2-256'
        result = self.agent.audit_ssh_cert_security(SshCertInput(code_content=code))
        assert any("SHA-1" in g or "sha1" in g.lower() or "ssh-rsa" in g for g in result.gaps)
        assert result.risk_score >= 65.0

    def test_flags_plaintext_webhook_secret(self) -> None:
        code = """
let response_mode = ResponseMode::Facebook("my_super_secret_token_123456");
config.webhook_secret = "hardcoded_secret_abc";
"""
        result = self.agent.audit_ssh_cert_security(SshCertInput(code_content=code))
        assert any("webhook" in g.lower() or "plaintext" in g.lower() for g in result.gaps)
        assert result.risk_score >= 70.0

    def test_flags_token_without_zeroize(self) -> None:
        code = """
struct ApiClient {
    auth_token: String,
    api_token: String,
}
"""
        result = self.agent.audit_ssh_cert_security(SshCertInput(code_content=code))
        assert any("Zeroize" in g or "zeroize" in g.lower() for g in result.gaps)

    def test_passes_token_with_zeroize(self) -> None:
        code = """
use secrecy::Secret;
struct ApiClient {
    auth_token: Secret<String>,
}
impl Drop for ApiClient {
    fn drop(&mut self) { self.auth_token.zeroize(); }
}
"""
        result = self.agent.audit_ssh_cert_security(SshCertInput(code_content=code))
        assert not any("Zeroize" in g for g in result.gaps)

    def test_has_cert_parsing_flag_triggers_checks(self) -> None:
        code = "// authorization module - check identity"
        result_without_flag = self.agent.audit_ssh_cert_security(
            SshCertInput(code_content=code, has_cert_parsing=False)
        )
        result_with_flag = self.agent.audit_ssh_cert_security(
            SshCertInput(code_content=code, has_cert_parsing=True)
        )
        assert len(result_with_flag.gaps) > len(result_without_flag.gaps)

    def test_agent_name(self) -> None:
        assert self.agent.agent_name == "PiSshCertificateSecurityAuditor"


# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------


class TestBatch2RouterRegistration:
    def test_both_agents_registered(self) -> None:
        from pi_micro_agents.orchestrator.router import AgentRouter

        names = {r.agent_name for r in AgentRouter.routes}
        assert "PiBotDetectionEvasionSentry" in names
        assert "PiSshCertificateSecurityAuditor" in names

    def test_bot_evasion_keyword_resolves(self) -> None:
        from pi_micro_agents.orchestrator.router import AgentRouter

        route = AgentRouter.resolve("waf bypass pattern scan of this automation script")
        assert route is not None
        assert route.agent_name == "PiBotDetectionEvasionSentry"

    def test_ssh_cert_keyword_resolves(self) -> None:
        from pi_micro_agents.orchestrator.router import AgentRouter

        route = AgentRouter.resolve("sshcerts security gap in this rust module")
        assert route is not None
        assert route.agent_name == "PiSshCertificateSecurityAuditor"

    def test_total_count_is_248(self) -> None:
        from pi_micro_agents.orchestrator.router import AgentRouter

        assert len(AgentRouter.routes) == 248
