"""Integration tests for consensus integration of the 10 Phase 3 micro-agents.

This file verifies that all 10 Phase 3 micro-agents are perfectly integrated
into consensus.py, validating happy path consensus, split-vote handling,
unstructured logging, rotation engines, and premium summary formatting.
"""

from __future__ import annotations

from pi_micro_agents.orchestrator.consensus import run_with_consensus
from pi_micro_agents.pi_automated_anonymizer import AnonymizerInput, PiAutomatedAnonymizer
from pi_micro_agents.pi_automated_rotation_engine import PiAutomatedRotationEngine, RotationInput
from pi_micro_agents.pi_container_escape_detector import ContainerEscapeInput, PiContainerEscapeDetector
from pi_micro_agents.pi_data_flow_privacy_mapper import PiDataFlowPrivacyMapper, PrivacyMapperInput
from pi_micro_agents.pi_docker_image_scanner import DockerImageInput, PiDockerImageScanner
from pi_micro_agents.pi_hardcoded_secret_detector import HardcodedSecretInput, PiHardcodedSecretDetector
from pi_micro_agents.pi_llm_output_sanitizer import LLMOutputSanitizerInput, PiLLMOutputSanitizer
from pi_micro_agents.pi_orchestrator import PiOrchestrator
from pi_micro_agents.pi_sensitive_data_scanner import PiSensitiveDataScanner, SensitiveDataInput
from pi_micro_agents.pi_sensitive_log_leak_sentry import LogLeakInput, PiSensitiveLogLeakSentry
from pi_micro_agents.pi_structured_logging_enforcer import PiStructuredLoggingEnforcer, StructuredLoggingInput


def test_docker_image_scanner_consensus():
    """Verify consensus execution, output parsing, and summaries for PiDockerImageScanner."""
    orchestrator = PiOrchestrator()
    input_envelope = DockerImageInput(
        file_path="Dockerfile", dockerfile_content="FROM ubuntu:latest\nRUN apt-get update"
    )

    mock_runs = [
        {"is_secure": True, "detected_vulnerabilities": [], "risk_score": 0.0, "status": "PASSED"},
        {"is_secure": True, "detected_vulnerabilities": [], "risk_score": 0.0, "status": "PASSED"},
        {"is_secure": True, "detected_vulnerabilities": [], "risk_score": 0.0, "status": "PASSED"},
    ]

    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiDockerImageScanner,
        input_envelope=input_envelope,
        goal="Scan docker image",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiDockerImageScanner",
    )

    assert success is True
    assert risk_score == 0.0
    assert "container image safety scan" in summary
    assert "PASSED" in summary
    assert "consensus_telemetry" in details
    assert len(anomalies) == 0


def test_container_escape_detector_consensus():
    """Verify consensus execution, output parsing, and summaries for PiContainerEscapeDetector."""
    orchestrator = PiOrchestrator()
    input_envelope = ContainerEscapeInput(file_path="pod.yaml", config_content="apiVersion: v1")

    mock_runs = [
        {"is_secure": True, "escape_vectors": [], "risk_score": 0.0, "status": "PASSED"},
        {"is_secure": True, "escape_vectors": [], "risk_score": 0.0, "status": "PASSED"},
        {"is_secure": True, "escape_vectors": [], "risk_score": 0.0, "status": "PASSED"},
    ]

    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiContainerEscapeDetector,
        input_envelope=input_envelope,
        goal="Detect container escapes",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiContainerEscapeDetector",
    )

    assert success is True
    assert risk_score == 0.0
    assert "container escape vulnerabilities scan" in summary
    assert "PASSED" in summary
    assert "consensus_telemetry" in details


def test_hardcoded_secret_detector_consensus():
    """Verify consensus execution, output parsing, and summaries for PiHardcodedSecretDetector."""
    orchestrator = PiOrchestrator()
    input_envelope = HardcodedSecretInput(file_path="app.py", file_content="password = '123'")

    mock_runs = [
        {"is_secure": False, "flagged_secrets": ["Potential secret key leak"], "risk_score": 75.0, "status": "FLAGGED"},
        {"is_secure": False, "flagged_secrets": ["Potential secret key leak"], "risk_score": 75.0, "status": "FLAGGED"},
        {"is_secure": False, "flagged_secrets": ["Potential secret key leak"], "risk_score": 75.0, "status": "FLAGGED"},
    ]

    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiHardcodedSecretDetector,
        input_envelope=input_envelope,
        goal="Audit hardcoded secrets",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiHardcodedSecretDetector",
    )

    assert success is False
    assert risk_score == 75.0
    assert "hardcoded secrets scan" in summary
    assert "FLAGGED" in summary
    assert len(anomalies) == 1
    assert anomalies[0] == "Potential secret key leak"


def test_automated_rotation_engine_consensus():
    """Verify consensus execution, output parsing, and summaries for PiAutomatedRotationEngine."""
    orchestrator = PiOrchestrator()
    input_envelope = RotationInput(credential_type="API_KEY", target_identifier="aws_key")

    mock_runs = [
        {
            "is_secure": True,
            "rotation_completed": True,
            "rotation_details": {"aws_key": "rotated"},
            "status": "COMPLETED",
        },
        {
            "is_secure": True,
            "rotation_completed": True,
            "rotation_details": {"aws_key": "rotated"},
            "status": "COMPLETED",
        },
        {
            "is_secure": True,
            "rotation_completed": True,
            "rotation_details": {"aws_key": "rotated"},
            "status": "COMPLETED",
        },
    ]

    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiAutomatedRotationEngine,
        input_envelope=input_envelope,
        goal="Rotate credential",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiAutomatedRotationEngine",
    )

    assert success is True
    assert risk_score == 0.0
    assert "rotation process executed" in summary
    assert "COMPLETED" in summary
    assert "aws_key" in summary


def test_llm_output_sanitizer_consensus():
    """Verify consensus execution, output parsing, and summaries for PiLLMOutputSanitizer."""
    orchestrator = PiOrchestrator()
    input_envelope = LLMOutputSanitizerInput(raw_output="Hello user", system_prompt_reference="")

    mock_runs = [
        {
            "is_secure": True,
            "sanitized_output": "Hello user",
            "risk_score": 0.0,
            "detected_leaks": [],
            "status": "CLEAN",
        },
        {
            "is_secure": True,
            "sanitized_output": "Hello user",
            "risk_score": 0.0,
            "detected_leaks": [],
            "status": "CLEAN",
        },
        {
            "is_secure": True,
            "sanitized_output": "Hello user",
            "risk_score": 0.0,
            "detected_leaks": [],
            "status": "CLEAN",
        },
    ]

    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiLLMOutputSanitizer,
        input_envelope=input_envelope,
        goal="Sanitize output",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiLLMOutputSanitizer",
    )

    assert success is True
    assert risk_score == 0.0
    assert "LLM output sanitization" in summary
    assert "CLEAN" in summary


def test_data_flow_privacy_mapper_consensus():
    """Verify consensus execution, output parsing, and summaries for PiDataFlowPrivacyMapper."""
    orchestrator = PiOrchestrator()
    input_envelope = PrivacyMapperInput(
        data_sources=["user_db"],
        data_destinations=["untrusted_console"],
        flow_connections=[{"from": "user_db", "to": "untrusted_console"}],
    )

    mock_runs = [
        {
            "is_secure": False,
            "unsecured_flows": ["user_db -> untrusted_console"],
            "risk_score": 80.0,
            "status": "COMPROMISED",
        },
        {
            "is_secure": False,
            "unsecured_flows": ["user_db -> untrusted_console"],
            "risk_score": 80.0,
            "status": "COMPROMISED",
        },
        {
            "is_secure": False,
            "unsecured_flows": ["user_db -> untrusted_console"],
            "risk_score": 80.0,
            "status": "COMPROMISED",
        },
    ]

    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiDataFlowPrivacyMapper,
        input_envelope=input_envelope,
        goal="Map privacy flows",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiDataFlowPrivacyMapper",
    )

    assert success is False
    assert risk_score == 80.0
    assert "data flow privacy analysis" in summary
    assert "COMPROMISED" in summary
    assert "user_db -> untrusted_console" in anomalies


def test_sensitive_data_scanner_consensus():
    """Verify consensus execution, output parsing, and summaries for PiSensitiveDataScanner."""
    orchestrator = PiOrchestrator()
    input_envelope = SensitiveDataInput(data_label="user_profile", text_content="ssn 123-456-7890")

    mock_runs = [
        {"is_secure": False, "discovered_pii_elements": ["SSN Leak"], "risk_score": 90.0, "status": "FLAGGED"},
        {"is_secure": False, "discovered_pii_elements": ["SSN Leak"], "risk_score": 90.0, "status": "FLAGGED"},
        {"is_secure": False, "discovered_pii_elements": ["SSN Leak"], "risk_score": 90.0, "status": "FLAGGED"},
    ]

    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiSensitiveDataScanner,
        input_envelope=input_envelope,
        goal="Scan PII",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiSensitiveDataScanner",
    )

    assert success is False
    assert risk_score == 90.0
    assert "sensitive data and PII scan" in summary
    assert "user_profile" in summary
    assert "FLAGGED" in summary


def test_automated_anonymizer_consensus():
    """Verify consensus execution, output parsing, and summaries for PiAutomatedAnonymizer."""
    orchestrator = PiOrchestrator()
    input_envelope = AnonymizerInput(raw_payload="email abc@test.com")

    mock_runs = [
        {
            "is_secure": True,
            "anonymized_payload": "email ******@test.com",
            "fields_scrubbed_count": 1,
            "status": "SCRUBBED",
        },
        {
            "is_secure": True,
            "anonymized_payload": "email ******@test.com",
            "fields_scrubbed_count": 1,
            "status": "SCRUBBED",
        },
        {
            "is_secure": True,
            "anonymized_payload": "email ******@test.com",
            "fields_scrubbed_count": 1,
            "status": "SCRUBBED",
        },
    ]

    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiAutomatedAnonymizer,
        input_envelope=input_envelope,
        goal="Anonymize PII",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiAutomatedAnonymizer",
    )

    assert success is True
    assert risk_score == 0.0
    assert "payload anonymization completed" in summary
    assert "Fields scrubbed: 1" in summary


def test_sensitive_log_leak_sentry_consensus():
    """Verify consensus execution, output parsing, and summaries for PiSensitiveLogLeakSentry."""
    orchestrator = PiOrchestrator()
    input_envelope = LogLeakInput(log_file_path="/var/log/app.log", log_content="password leaked!")

    mock_runs = [
        {"is_secure": False, "flagged_leaks": ["password leak"], "risk_score": 88.0, "status": "FLAGGED"},
        {"is_secure": False, "flagged_leaks": ["password leak"], "risk_score": 88.0, "status": "FLAGGED"},
        {"is_secure": False, "flagged_leaks": ["password leak"], "risk_score": 88.0, "status": "FLAGGED"},
    ]

    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiSensitiveLogLeakSentry,
        input_envelope=input_envelope,
        goal="Audit log leaks",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiSensitiveLogLeakSentry",
    )

    assert success is False
    assert risk_score == 88.0
    assert "sensitive log leak audit" in summary
    assert "FLAGGED" in summary


def test_structured_logging_enforcer_consensus():
    """Verify consensus execution, output parsing, and summaries for PiStructuredLoggingEnforcer."""
    orchestrator = PiOrchestrator()
    input_envelope = StructuredLoggingInput(file_path="src/main.py", code_content="print('unstructured')")

    mock_runs = [
        {
            "is_secure": False,
            "unstructured_statements": ["Line 1: print used"],
            "compliance_score": 85.0,
            "status": "NON_COMPLIANT",
        },
        {
            "is_secure": False,
            "unstructured_statements": ["Line 1: print used"],
            "compliance_score": 85.0,
            "status": "NON_COMPLIANT",
        },
        {
            "is_secure": False,
            "unstructured_statements": ["Line 1: print used"],
            "compliance_score": 85.0,
            "status": "NON_COMPLIANT",
        },
    ]

    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiStructuredLoggingEnforcer,
        input_envelope=input_envelope,
        goal="Enforce structured logging",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiStructuredLoggingEnforcer",
    )

    assert success is False
    assert risk_score == 15.0
    assert "structured logging compliance audit" in summary
    assert "Compliance score: 85.0" in summary
    assert "NON_COMPLIANT" in summary


def test_consensus_split_vote_handling():
    """Verify split vote / consensus alarm blocker triggers appropriately."""
    orchestrator = PiOrchestrator()
    input_envelope = StructuredLoggingInput(file_path="src/main.py", code_content="print('unstructured')")

    mock_runs = [
        {"is_secure": True, "unstructured_statements": [], "compliance_score": 100.0, "status": "COMPLIANT"},
        {
            "is_secure": False,
            "unstructured_statements": ["print used"],
            "compliance_score": 85.0,
            "status": "NON_COMPLIANT",
        },
        {"is_secure": True, "unstructured_statements": [], "compliance_score": 100.0, "status": "COMPLIANT"},
    ]

    success, risk_score, summary, details, anomalies = run_with_consensus(
        orchestrator=orchestrator,
        agent_class=PiStructuredLoggingEnforcer,
        input_envelope=input_envelope,
        goal="Enforce structured logging",
        context={"mock_consensus_runs": mock_runs},
        agent_name="PiStructuredLoggingEnforcer",
    )

    # Vote is split (2 secure vs 1 insecure), consensus achieved on True (majority index 0)
    assert success is True
    assert risk_score == 0.0
    assert "Compliance score: 100.0" in summary
