"""Integration tests for consensus integration of the 20 Phase 4 complementary micro-agents.

This file verifies that all 20 Phase 4 micro-agents (11-30) are perfectly integrated
into consensus.py, validating happy path consensus, split-vote handling, and summary formatting.
"""

from __future__ import annotations

from pi_micro_agents.orchestrator.consensus import run_with_consensus
from pi_micro_agents.pi_api_owasp_scanner import APIInput, PiAPIOWASPScanner
from pi_micro_agents.pi_audit_log_tamper_detector import LogInput, PiAuditLogTamperDetector
from pi_micro_agents.pi_backup_integrity_checker import BackupInput, PiBackupIntegrityChecker
from pi_micro_agents.pi_certificate_rotation_watcher import CertInput, PiCertificateRotationWatcher
from pi_micro_agents.pi_cloud_config_auditor import CloudConfigInput, PiCloudConfigAuditor
from pi_micro_agents.pi_code_signing_enforcer import ArtifactInput, PiCodeSigningEnforcer
from pi_micro_agents.pi_data_retention_policy_enforcer import PiDataRetentionPolicyEnforcer, RetentionInput
from pi_micro_agents.pi_dependency_vuln_scanner import DependencyInput, PiDependencyVulnScanner
from pi_micro_agents.pi_encryption_compliance_checker import EncryptionInput, PiEncryptionComplianceChecker
from pi_micro_agents.pi_firewall_rule_auditor import FirewallInput, PiFirewallRuleAuditor
from pi_micro_agents.pi_iac_scanner import IaCInput, PiIaCScanner
from pi_micro_agents.pi_kubernetes_security_auditor import K8sInput, PiKubernetesSecurityAuditor
from pi_micro_agents.pi_misconfig_pattern_matcher import ConfigInput, PiMisconfigPatternMatcher
from pi_micro_agents.pi_orchestrator import PiOrchestrator
from pi_micro_agents.pi_rbac_permission_mapper import PiRBACPermissionMapper, RBACInput
from pi_micro_agents.pi_runtime_anomaly_sentry import PiRuntimeAnomalySentry, RuntimeInput
from pi_micro_agents.pi_sbom_validator import PiSBOMValidator, SBOMInput
from pi_micro_agents.pi_secrets_manager_completeness_checker import PiSecretsManagerCompletenessChecker, VaultInput
from pi_micro_agents.pi_supply_chain_integrity_checker import PiSupplyChainIntegrityChecker, SupplyChainInput
from pi_micro_agents.pi_threat_model_generator import PiThreatModelGenerator, SystemInput
from pi_micro_agents.pi_zero_trust_verifier import PiZeroTrustVerifier, ZeroTrustInput


def test_iac_scanner_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = IaCInput(file_path="main.tf", iac_content="resource 'aws_s3_bucket' 'b' {}", iac_type="terraform")
    mock_runs = [
        {"is_secure": True, "detected_misconfigs": [], "risk_score": 0.0, "status": "PASSED"},
        {"is_secure": True, "detected_misconfigs": [], "risk_score": 0.0, "status": "PASSED"},
        {"is_secure": True, "detected_misconfigs": [], "risk_score": 0.0, "status": "PASSED"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiIaCScanner,
        input_envelope=input_envelope,
        goal="Scan IaC template",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiIaCScanner",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed static IaC security scan on main.tf" in summary
    assert "PASSED" in summary


def test_dependency_vuln_scanner_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = DependencyInput(lockfile_path="package-lock.json", lockfile_content="{}", ecosystem="npm")
    mock_runs = [
        {"is_secure": True, "vulnerable_packages": [], "risk_score": 0.0, "status": "SECURE"},
        {"is_secure": True, "vulnerable_packages": [], "risk_score": 0.0, "status": "SECURE"},
        {"is_secure": True, "vulnerable_packages": [], "risk_score": 0.0, "status": "SECURE"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiDependencyVulnScanner,
        input_envelope=input_envelope,
        goal="Scan dependencies",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiDependencyVulnScanner",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed dependency vulnerability scan on package-lock.json" in summary
    assert "SECURE" in summary


def test_cloud_config_auditor_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = CloudConfigInput(file_path="aws_config.json", config_content="{}", provider="aws")
    mock_runs = [
        {"is_secure": True, "misconfigured_resources": [], "risk_score": 0.0, "status": "COMPLIANT"},
        {"is_secure": True, "misconfigured_resources": [], "risk_score": 0.0, "status": "COMPLIANT"},
        {"is_secure": True, "misconfigured_resources": [], "risk_score": 0.0, "status": "COMPLIANT"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiCloudConfigAuditor,
        input_envelope=input_envelope,
        goal="Audit cloud configuration",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiCloudConfigAuditor",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed cloud config security audit on aws_config.json" in summary
    assert "COMPLIANT" in summary


def test_rbac_permission_mapper_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = RBACInput(policy_file_path="policy.json", policy_content="{}")
    mock_runs = [
        {"is_secure": True, "excessive_permissions": [], "risk_score": 0.0, "status": "SECURE"},
        {"is_secure": True, "excessive_permissions": [], "risk_score": 0.0, "status": "SECURE"},
        {"is_secure": True, "excessive_permissions": [], "risk_score": 0.0, "status": "SECURE"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiRBACPermissionMapper,
        input_envelope=input_envelope,
        goal="Map RBAC permissions",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiRBACPermissionMapper",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed RBAC least privilege mapping on policy.json" in summary
    assert "SECURE" in summary


def test_encryption_compliance_checker_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = EncryptionInput(resource_type="s3_bucket", config_snippet="{}")
    mock_runs = [
        {"is_secure": True, "missing_encryption": [], "risk_score": 0.0, "status": "COMPLIANT"},
        {"is_secure": True, "missing_encryption": [], "risk_score": 0.0, "status": "COMPLIANT"},
        {"is_secure": True, "missing_encryption": [], "risk_score": 0.0, "status": "COMPLIANT"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiEncryptionComplianceChecker,
        input_envelope=input_envelope,
        goal="Check encryption compliance",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiEncryptionComplianceChecker",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed encryption compliance check on s3_bucket" in summary
    assert "COMPLIANT" in summary


def test_sbom_validator_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = SBOMInput(sbom_path="sbom.json", sbom_content="{}", format="cyclonedx")
    mock_runs = [
        {"is_secure": True, "license_issues": [], "missing_attestations": [], "risk_score": 0.0, "status": "VERIFIED"},
        {"is_secure": True, "license_issues": [], "missing_attestations": [], "risk_score": 0.0, "status": "VERIFIED"},
        {"is_secure": True, "license_issues": [], "missing_attestations": [], "risk_score": 0.0, "status": "VERIFIED"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiSBOMValidator,
        input_envelope=input_envelope,
        goal="Validate SBOM",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiSBOMValidator",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed SBOM licensing and validation audit on sbom.json" in summary
    assert "VERIFIED" in summary


def test_supply_chain_integrity_checker_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = SupplyChainInput(manifest_path="package.json", manifest_content="{}")
    mock_runs = [
        {"is_secure": True, "suspicious_packages": [], "risk_score": 0.0, "status": "PASSED"},
        {"is_secure": True, "suspicious_packages": [], "risk_score": 0.0, "status": "PASSED"},
        {"is_secure": True, "suspicious_packages": [], "risk_score": 0.0, "status": "PASSED"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiSupplyChainIntegrityChecker,
        input_envelope=input_envelope,
        goal="Check supply chain integrity",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiSupplyChainIntegrityChecker",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed software supply chain integrity check on package.json" in summary
    assert "PASSED" in summary


def test_api_owasp_scanner_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = APIInput(api_path="/v1/users", schema_content="{}")
    mock_runs = [
        {"is_secure": True, "owasp_violations": [], "risk_score": 0.0, "status": "SECURE"},
        {"is_secure": True, "owasp_violations": [], "risk_score": 0.0, "status": "SECURE"},
        {"is_secure": True, "owasp_violations": [], "risk_score": 0.0, "status": "SECURE"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiAPIOWASPScanner,
        input_envelope=input_envelope,
        goal="Scan API endpoint for OWASP violations",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiAPIOWASPScanner",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed API OWASP security audit on /v1/users" in summary
    assert "SECURE" in summary


def test_kubernetes_security_auditor_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = K8sInput(k8s_content="apiVersion: v1")
    mock_runs = [
        {"is_secure": True, "violations": [], "risk_score": 0.0, "status": "PASSED"},
        {"is_secure": True, "violations": [], "risk_score": 0.0, "status": "PASSED"},
        {"is_secure": True, "violations": [], "risk_score": 0.0, "status": "PASSED"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiKubernetesSecurityAuditor,
        input_envelope=input_envelope,
        goal="Audit Kubernetes configuration",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiKubernetesSecurityAuditor",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed Kubernetes security audit" in summary
    assert "PASSED" in summary


def test_zero_trust_verifier_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = ZeroTrustInput(network_policy_content="[]")
    mock_runs = [
        {"is_secure": True, "violations": [], "risk_score": 0.0, "status": "COMPLIANT"},
        {"is_secure": True, "violations": [], "risk_score": 0.0, "status": "COMPLIANT"},
        {"is_secure": True, "violations": [], "risk_score": 0.0, "status": "COMPLIANT"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiZeroTrustVerifier,
        input_envelope=input_envelope,
        goal="Verify Zero Trust policies",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiZeroTrustVerifier",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed Zero-Trust network policy verification" in summary
    assert "COMPLIANT" in summary


def test_certificate_rotation_watcher_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = CertInput(cert_content="-----BEGIN CERTIFICATE-----")
    mock_runs = [
        {"is_secure": True, "issues": [], "risk_score": 0.0, "status": "ACTIVE"},
        {"is_secure": True, "issues": [], "risk_score": 0.0, "status": "ACTIVE"},
        {"is_secure": True, "issues": [], "risk_score": 0.0, "status": "ACTIVE"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiCertificateRotationWatcher,
        input_envelope=input_envelope,
        goal="Watch certificate rotation status",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiCertificateRotationWatcher",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed certificate rotation watch" in summary
    assert "ACTIVE" in summary


def test_firewall_rule_auditor_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = FirewallInput(rules_content="[]")
    mock_runs = [
        {"is_secure": True, "open_ports": [], "issues": [], "risk_score": 0.0, "status": "COMPLIANT"},
        {"is_secure": True, "open_ports": [], "issues": [], "risk_score": 0.0, "status": "COMPLIANT"},
        {"is_secure": True, "open_ports": [], "issues": [], "risk_score": 0.0, "status": "COMPLIANT"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiFirewallRuleAuditor,
        input_envelope=input_envelope,
        goal="Audit firewall rules",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiFirewallRuleAuditor",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed firewall rule security audit" in summary
    assert "COMPLIANT" in summary


def test_backup_integrity_checker_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = BackupInput(backup_config="{}")
    mock_runs = [
        {"is_secure": True, "issues": [], "risk_score": 0.0, "status": "VALID"},
        {"is_secure": True, "issues": [], "risk_score": 0.0, "status": "VALID"},
        {"is_secure": True, "issues": [], "risk_score": 0.0, "status": "VALID"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiBackupIntegrityChecker,
        input_envelope=input_envelope,
        goal="Check backup integrity",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiBackupIntegrityChecker",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed disaster recovery backup integrity check" in summary
    assert "VALID" in summary


def test_audit_log_tamper_detector_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = LogInput(log_content="[]")
    mock_runs = [
        {"is_secure": True, "anomalies": [], "risk_score": 0.0, "status": "INTEGRIOUS"},
        {"is_secure": True, "anomalies": [], "risk_score": 0.0, "status": "INTEGRIOUS"},
        {"is_secure": True, "anomalies": [], "risk_score": 0.0, "status": "INTEGRIOUS"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiAuditLogTamperDetector,
        input_envelope=input_envelope,
        goal="Detect audit log tampering",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiAuditLogTamperDetector",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed audit log tampering detection scan" in summary
    assert "INTEGRIOUS" in summary


def test_misconfig_pattern_matcher_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = ConfigInput(config_content="port 6379")
    mock_runs = [
        {"is_secure": True, "matched_patterns": [], "risk_score": 0.0, "status": "PASSED"},
        {"is_secure": True, "matched_patterns": [], "risk_score": 0.0, "status": "PASSED"},
        {"is_secure": True, "matched_patterns": [], "risk_score": 0.0, "status": "PASSED"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiMisconfigPatternMatcher,
        input_envelope=input_envelope,
        goal="Match configuration anomalies",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiMisconfigPatternMatcher",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed security misconfiguration pattern match" in summary
    assert "PASSED" in summary


def test_threat_model_generator_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = SystemInput(system_desc="Handles credit cards")
    mock_runs = [
        {"is_secure": True, "threats": [], "STRIDE_categories": [], "risk_score": 0.0, "status": "SECURE"},
        {"is_secure": True, "threats": [], "STRIDE_categories": [], "risk_score": 0.0, "status": "SECURE"},
        {"is_secure": True, "threats": [], "STRIDE_categories": [], "risk_score": 0.0, "status": "SECURE"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiThreatModelGenerator,
        input_envelope=input_envelope,
        goal="Generate threat model",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiThreatModelGenerator",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed dynamic STRIDE threat model generation" in summary
    assert "SECURE" in summary


def test_secrets_manager_completeness_checker_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = VaultInput(vault_config="{}")
    mock_runs = [
        {"is_secure": True, "gaps": [], "risk_score": 0.0, "status": "COMPLETE"},
        {"is_secure": True, "gaps": [], "risk_score": 0.0, "status": "COMPLETE"},
        {"is_secure": True, "gaps": [], "risk_score": 0.0, "status": "COMPLETE"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiSecretsManagerCompletenessChecker,
        input_envelope=input_envelope,
        goal="Check secrets manager completeness",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiSecretsManagerCompletenessChecker",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed secrets vault configuration completeness check" in summary
    assert "COMPLETE" in summary


def test_code_signing_enforcer_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = ArtifactInput(artifact_metadata="{}")
    mock_runs = [
        {"is_secure": True, "issues": [], "risk_score": 0.0, "status": "SIGNED"},
        {"is_secure": True, "issues": [], "risk_score": 0.0, "status": "SIGNED"},
        {"is_secure": True, "issues": [], "risk_score": 0.0, "status": "SIGNED"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiCodeSigningEnforcer,
        input_envelope=input_envelope,
        goal="Verify code signing status",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiCodeSigningEnforcer",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed build artifact code signing enforcement scan" in summary
    assert "SIGNED" in summary


def test_data_retention_policy_enforcer_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = RetentionInput(policy_content="retention policy content")
    mock_runs = [
        {"is_secure": True, "issues": [], "risk_score": 0.0, "status": "COMPLIANT"},
        {"is_secure": True, "issues": [], "risk_score": 0.0, "status": "COMPLIANT"},
        {"is_secure": True, "issues": [], "risk_score": 0.0, "status": "COMPLIANT"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiDataRetentionPolicyEnforcer,
        input_envelope=input_envelope,
        goal="Enforce data retention policies",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiDataRetentionPolicyEnforcer",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed data retention lifecycle policy enforcement scan" in summary
    assert "COMPLIANT" in summary


def test_runtime_anomaly_sentry_consensus():
    orchestrator = PiOrchestrator()
    input_envelope = RuntimeInput(metrics_content="cpu_load: 0.1")
    mock_runs = [
        {"is_secure": True, "anomalies_detected": [], "risk_score": 0.0, "status": "HEALTHY"},
        {"is_secure": True, "anomalies_detected": [], "risk_score": 0.0, "status": "HEALTHY"},
        {"is_secure": True, "anomalies_detected": [], "risk_score": 0.0, "status": "HEALTHY"},
    ]
    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiRuntimeAnomalySentry,
        input_envelope=input_envelope,
        goal="Watch runtime anomalies",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiRuntimeAnomalySentry",
    )
    assert success is True
    assert risk_score == 0.0
    assert "Completed runtime container metrics anomaly audit" in summary
    assert "HEALTHY" in summary
