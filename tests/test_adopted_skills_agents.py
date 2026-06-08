from __future__ import annotations

from pi_micro_agents.pi_hipaa_compliance_auditor import HipaaAuditInput, PiHipaaComplianceAuditor
from pi_micro_agents.pi_mobile_security_auditor import MobileAuditInput, PiMobileSecurityAuditor
from pi_micro_agents.pi_pci_dss_auditor import PciDssInput, PiPciDssAuditor

# ---------------------------------------------------------------------------
# PiHipaaComplianceAuditor
# ---------------------------------------------------------------------------


class TestPiHipaaComplianceAuditor:
    def setup_method(self) -> None:
        self.agent = PiHipaaComplianceAuditor()

    def test_passes_clean_code(self) -> None:
        result = self.agent.audit_hipaa_compliance(
            HipaaAuditInput(code_content="def process_order(order_id: str) -> None: pass")
        )
        assert result.status == "PASSED"
        assert result.is_secure is True
        assert result.risk_score == 0.0
        assert result.phi_identifiers_found == []

    def test_flags_phi_in_log_call(self) -> None:
        code = """
import logging
logger = logging.getLogger(__name__)

def handle_patient(patient_name: str, dob: str) -> None:
    logger.info(f"Processing {patient_name} born {dob}")
"""
        result = self.agent.audit_hipaa_compliance(
            HipaaAuditInput(code_content=code, component_type="api")
        )
        assert result.status in ("WARN_PHI_EXPOSURE", "REJECTED_PHI_EXPOSURE")
        assert any("name" in v for v in result.phi_identifiers_found)
        assert result.risk_score >= 85.0

    def test_flags_cleartext_http(self) -> None:
        code = 'url = "http://api.health-records.internal/patients"'
        result = self.agent.audit_hipaa_compliance(
            HipaaAuditInput(code_content=code, component_type="api")
        )
        assert result.status in ("WARN_PHI_EXPOSURE", "REJECTED_PHI_EXPOSURE")
        assert any("transit" in v for v in result.violations)
        assert result.risk_score >= 90.0

    def test_flags_db_storage_without_encryption(self) -> None:
        code = """
CREATE TABLE patients (
    mrn VARCHAR(20),
    patient_name TEXT,
    date_of_birth DATE
);
"""
        result = self.agent.audit_hipaa_compliance(
            HipaaAuditInput(code_content=code, component_type="db")
        )
        assert result.status in ("WARN_PHI_EXPOSURE", "REJECTED_PHI_EXPOSURE")
        assert any("encryption" in v.lower() for v in result.violations)

    def test_passes_encrypted_storage(self) -> None:
        code = """
# Uses KMS-encrypted column
CREATE TABLE patients (
    mrn VARCHAR(20),
    patient_name_encrypted BYTEA  -- AES-256-GCM via KMS
);
-- encrypt all PHI fields via vault + kms
"""
        result = self.agent.audit_hipaa_compliance(
            HipaaAuditInput(code_content=code, component_type="db")
        )
        assert result.risk_score < 85.0

    def test_agent_name(self) -> None:
        assert self.agent.agent_name == "PiHipaaComplianceAuditor"


# ---------------------------------------------------------------------------
# PiPciDssAuditor
# ---------------------------------------------------------------------------


class TestPiPciDssAuditor:
    def setup_method(self) -> None:
        self.agent = PiPciDssAuditor()

    def test_passes_clean_code(self) -> None:
        result = self.agent.audit_pci_dss(
            PciDssInput(code_content="def get_order(order_id: str) -> dict: pass")
        )
        assert result.status == "PASSED"
        assert result.is_secure is True
        assert result.risk_score == 0.0

    def test_flags_cvv_in_storage(self) -> None:
        code = """
db.execute(
    "INSERT INTO card_tokens (pan, cvv2, expiry) VALUES (?, ?, ?)",
    (pan, cvv2, expiry)
)
"""
        result = self.agent.audit_pci_dss(
            PciDssInput(code_content=code, component_type="db")
        )
        assert result.status in ("WARN_CHD_RISK", "REJECTED_CHD_VIOLATION")
        assert result.risk_score >= 95.0
        assert any("CVV" in v or "cvv" in v.lower() for v in result.chd_violations)

    def test_flags_pan_in_logs(self) -> None:
        code = """
import logging
logger = logging.getLogger(__name__)
logger.info(f"Processing card_number={card_number}")
"""
        result = self.agent.audit_pci_dss(
            PciDssInput(code_content=code, component_type="payment")
        )
        assert result.status in ("WARN_CHD_RISK", "REJECTED_CHD_VIOLATION")
        assert result.risk_score >= 85.0
        assert any("PAN" in v for v in result.chd_violations)

    def test_flags_weak_crypto(self) -> None:
        code = 'digest = hashlib.md5(pan.encode()).hexdigest()'
        result = self.agent.audit_pci_dss(
            PciDssInput(code_content=code, component_type="payment")
        )
        assert result.status in ("WARN_CHD_RISK", "REJECTED_CHD_VIOLATION")
        assert any("Req 12.3.3" in r for r in result.pci_requirements_violated)

    def test_flags_weak_tls(self) -> None:
        code = 'ssl_context.minimum_version = TLS_1_0'
        result = self.agent.audit_pci_dss(
            PciDssInput(code_content=code, component_type="api")
        )
        assert result.status in ("WARN_CHD_RISK", "REJECTED_CHD_VIOLATION")
        assert any("TLS" in v for v in result.chd_violations)

    def test_no_duplicate_requirements(self) -> None:
        code = """
import logging
logger = logging.getLogger(__name__)
logger.info(card_number)
logger.debug(card_number)
"""
        result = self.agent.audit_pci_dss(
            PciDssInput(code_content=code, component_type="payment")
        )
        req_list = result.pci_requirements_violated
        assert len(req_list) == len(set(req_list))

    def test_agent_name(self) -> None:
        assert self.agent.agent_name == "PiPciDssAuditor"


# ---------------------------------------------------------------------------
# PiMobileSecurityAuditor
# ---------------------------------------------------------------------------


class TestPiMobileSecurityAuditor:
    def setup_method(self) -> None:
        self.agent = PiMobileSecurityAuditor()

    def test_passes_clean_code(self) -> None:
        result = self.agent.audit_mobile_security(
            MobileAuditInput(code_content="fun greet(name: String) = println(\"Hello $name\")")
        )
        assert result.status == "PASSED"
        assert result.is_secure is True
        assert result.risk_score == 0.0

    def test_flags_trust_all_certs(self) -> None:
        code = """
val trustManager = TrustAllCerts()
sslContext.init(null, arrayOf(trustManager), null)
"""
        result = self.agent.audit_mobile_security(
            MobileAuditInput(code_content=code, platform="android")
        )
        assert result.status in ("WARN_MASVS_RISK", "REJECTED_MASVS_VIOLATION")
        assert result.risk_score >= 95.0
        assert any("MASVS-NETWORK-1" in v for v in result.masvs_violations)

    def test_flags_shared_preferences_insecure(self) -> None:
        code = """
val prefs = getSharedPreferences("user_prefs", Context.MODE_PRIVATE)
prefs.edit().putString("auth_token", token).apply()
"""
        result = self.agent.audit_mobile_security(
            MobileAuditInput(code_content=code, platform="android")
        )
        assert result.status in ("WARN_MASVS_RISK", "REJECTED_MASVS_VIOLATION")
        assert any("MASVS-STORAGE-1" in v for v in result.masvs_violations)

    def test_passes_encrypted_shared_prefs(self) -> None:
        code = """
val masterKey = MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build()
val prefs = EncryptedSharedPreferences.create(context, "secure", masterKey, ...)
prefs.edit().putString("auth_token", token).apply()
"""
        result = self.agent.audit_mobile_security(
            MobileAuditInput(code_content=code, platform="android")
        )
        assert "MASVS-STORAGE-1" not in " ".join(result.masvs_violations)

    def test_flags_hardcoded_key(self) -> None:
        code = 'private val api_key = "sk-live-abc123def456ghi789jkl012"'
        result = self.agent.audit_mobile_security(
            MobileAuditInput(code_content=code, platform="android")
        )
        assert result.status in ("WARN_MASVS_RISK", "REJECTED_MASVS_VIOLATION")
        assert any("MASVS-CRYPTO-1" in v for v in result.masvs_violations)
        assert result.risk_score >= 90.0

    def test_flags_cleartext_traffic_ios(self) -> None:
        code = """
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
"""
        result = self.agent.audit_mobile_security(
            MobileAuditInput(code_content=code, platform="ios")
        )
        assert result.status in ("WARN_MASVS_RISK", "REJECTED_MASVS_VIOLATION")
        assert any("MASVS-NETWORK-2" in v for v in result.masvs_violations)

    def test_flags_weak_crypto_md5(self) -> None:
        code = "val hash = MessageDigest.getInstance(\"MD5\").digest(data)"
        result = self.agent.audit_mobile_security(
            MobileAuditInput(code_content=code, platform="android")
        )
        assert any("MASVS-CRYPTO-2" in v for v in result.masvs_violations)

    def test_platform_inference_from_file_path(self) -> None:
        code = "let prefs = NSUserDefaults.standard\nprefs.set(token, forKey: \"auth_token\")"
        result = self.agent.audit_mobile_security(
            MobileAuditInput(code_content=code, file_path="ios/AppDelegate.swift")
        )
        assert any("MASVS-STORAGE-1" in v for v in result.masvs_violations)

    def test_agent_name(self) -> None:
        assert self.agent.agent_name == "PiMobileSecurityAuditor"


# ---------------------------------------------------------------------------
# Router registration smoke test
# ---------------------------------------------------------------------------


class TestRouterRegistration:
    def test_three_new_agents_registered(self) -> None:
        from pi_micro_agents.orchestrator.router import AgentRouter

        names = {r.agent_name for r in AgentRouter.routes}
        assert "PiHipaaComplianceAuditor" in names
        assert "PiPciDssAuditor" in names
        assert "PiMobileSecurityAuditor" in names

    def test_hipaa_keywords_resolve(self) -> None:
        from pi_micro_agents.orchestrator.router import AgentRouter

        route = AgentRouter.resolve("hipaa compliance audit of this patient data handler")
        assert route is not None
        assert route.agent_name == "PiHipaaComplianceAuditor"

    def test_pci_keywords_resolve(self) -> None:
        from pi_micro_agents.orchestrator.router import AgentRouter

        route = AgentRouter.resolve("pci dss audit of payment processing module")
        assert route is not None
        assert route.agent_name == "PiPciDssAuditor"

    def test_mobile_keywords_resolve(self) -> None:
        from pi_micro_agents.orchestrator.router import AgentRouter

        route = AgentRouter.resolve("masvs audit of android keystore usage")
        assert route is not None
        assert route.agent_name == "PiMobileSecurityAuditor"

    def test_total_route_count_increased(self) -> None:
        from pi_micro_agents.orchestrator.router import AgentRouter

        assert len(AgentRouter.routes) >= 246
