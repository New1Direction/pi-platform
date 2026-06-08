"""Integration tests for Tier 1 GCP Deterministic Validator Agents."""

from __future__ import annotations

import json

from pi_micro_agents.pi_bigquery_schema_validator import BigQuerySchemaInput, PiBigQuerySchemaValidator
from pi_micro_agents.pi_cloud_run_config_auditor import CloudRunConfigInput, PiCloudRunConfigAuditor
from pi_micro_agents.pi_gcp_credential_file_auditor import GCPCredentialFileInput, PiGCPCredentialFileAuditor
from pi_micro_agents.pi_gcp_iam_policy_risk_auditor import GCPIAMPolicyInput, PiGCPIAMPolicyRiskAuditor
from pi_micro_agents.pi_gcp_project_id_validator import GCPProjectIDInput, PiGCPProjectIDValidator
from pi_micro_agents.pi_gcp_vpc_connector_validator import PiGCPVPCConnectorValidator, VPCConnectorInput
from pi_micro_agents.pi_gcp_workload_identity_auditor import PiGCPWorkloadIdentityAuditor, WorkloadIdentityInput
from pi_micro_agents.pi_memorystore_connection_auditor import MemorystoreConnectionInput, PiMemorystoreConnectionAuditor
from pi_micro_agents.pi_pubsub_topic_naming_auditor import PiPubSubTopicNamingAuditor, PubSubTopicNamingInput
from pi_micro_agents.pi_vertex_ai_model_id_validator import PiVertexAIModelIDValidator, VertexAIModelIDInput

# ─── 1. GCP Credential File Auditor Tests ────────────────────────────────────


class TestPiGCPCredentialFileAuditor:
    def _agent(self):
        return PiGCPCredentialFileAuditor()

    def test_invalid_json_handled(self):
        out = self._agent().execute(GCPCredentialFileInput(credential_json="invalid json", source="key.json"))
        assert not out.is_valid
        assert out.status == "ERROR"
        assert out.risk_score == 50.0

    def test_user_credential_warning(self):
        user_cred = '{"type": "authorized_user", "project_id": "my-project", "client_email": "user@example.com"}'
        out = self._agent().execute(GCPCredentialFileInput(credential_json=user_cred))
        assert not out.is_valid
        assert out.credential_type == "authorized_user"
        assert out.status == "FAIL"
        assert out.risk_score >= 30.0

    def test_valid_service_account(self):
        sa_cred = {
            "type": "service_account",
            "project_id": "my-gcp-project",
            "private_key_id": "12345678901234",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC5\n-----END PRIVATE KEY-----\n",
            "client_email": "sa-name@my-gcp-project.iam.gserviceaccount.com",
            "client_id": "112233445566",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "universe_domain": "googleapis.com",
        }
        out = self._agent().execute(GCPCredentialFileInput(credential_json=json.dumps(sa_cred)))
        assert out.is_valid
        assert out.credential_type == "service_account"
        assert out.status == "PASS"
        assert out.risk_score == 0.0


# ─── 2. GCP Project ID Validator Tests ───────────────────────────────────────


class TestPiGCPProjectIDValidator:
    def _agent(self):
        return PiGCPProjectIDValidator()

    def test_valid_project_id(self):
        out = self._agent().execute(GCPProjectIDInput(project_id="my-gcp-project-123"))
        assert out.is_valid
        assert out.risk_score == 0.0
        assert out.status == "PASS"

    def test_invalid_length_or_chars(self):
        out = self._agent().execute(GCPProjectIDInput(project_id="a"))
        assert not out.is_valid
        assert out.status == "FAIL"

        out = self._agent().execute(GCPProjectIDInput(project_id="consecutive--hyphens"))
        assert not out.is_valid
        assert out.status == "FAIL"

    def test_generic_name_warning(self):
        out = self._agent().execute(GCPProjectIDInput(project_id="staging", strict_naming=True))
        assert out.is_valid
        assert out.status in ["WARN", "FAIL"]


# ─── 3. Vertex AI Model ID Validator Tests ───────────────────────────────────


class TestPiVertexAIModelIDValidator:
    def _agent(self):
        return PiVertexAIModelIDValidator()

    def test_valid_active_model(self):
        out = self._agent().execute(VertexAIModelIDInput(model_id="gemini-2.5-flash", task_type="generation"))
        assert out.is_valid
        assert out.model_family == "gemini-2.5"
        assert not out.is_deprecated
        assert out.status == "PASS"

    def test_deprecated_model(self):
        out = self._agent().execute(VertexAIModelIDInput(model_id="gemini-1.0-pro", task_type="generation"))
        assert not out.is_valid
        assert out.is_deprecated
        assert out.recommended_alternative == "gemini-2.0-flash"
        assert out.status in ["WARN", "FAIL"]

    def test_mismatched_task_type(self):
        out = self._agent().execute(VertexAIModelIDInput(model_id="text-embedding-004", task_type="generation"))
        # text-embedding-004 does not support generation, resulting in risk_score=25 (PASS status but has issues)
        assert out.status == "PASS"
        assert out.risk_score == 25.0
        assert len(out.issues) == 1


# ─── 4. Pub/Sub Topic Naming Auditor Tests ───────────────────────────────────


class TestPiPubSubTopicNamingAuditor:
    def _agent(self):
        return PiPubSubTopicNamingAuditor()

    def test_valid_topic_and_subs(self):
        out = self._agent().execute(
            PubSubTopicNamingInput(
                topic_name="user-events", subscription_names=["user-events-sub", "user-events-subscription"]
            )
        )
        assert out.is_valid
        assert out.status == "PASS"
        assert out.naming_score == 100.0

    def test_reserved_prefix_and_bad_chars(self):
        out = self._agent().execute(
            PubSubTopicNamingInput(topic_name="goog-my-topic", subscription_names=["bad-sub-no-suffix"])
        )
        assert not out.is_valid  # Starts with goog
        assert any("reserved" in issue.lower() for issue in out.topic_issues)


# ─── 5. BigQuery Schema Validator Tests ──────────────────────────────────────


class TestPiBigQuerySchemaValidator:
    def _agent(self):
        return PiBigQuerySchemaValidator()

    def test_valid_schema(self):
        schema = [
            {"name": "user_id", "type": "STRING", "mode": "REQUIRED"},
            {"name": "created_at", "type": "TIMESTAMP", "mode": "NULLABLE"},
        ]
        out = self._agent().execute(BigQuerySchemaInput(schema_json=json.dumps(schema)))
        assert out.is_valid
        assert out.field_count == 2
        assert out.status == "PASS"

    def test_pii_fields_detected(self):
        schema = [
            {"name": "email", "type": "STRING", "mode": "REQUIRED"},
            {"name": "ssn", "type": "STRING", "mode": "NULLABLE"},
        ]
        out = self._agent().execute(BigQuerySchemaInput(schema_json=json.dumps(schema), check_pii_fields=True))
        assert out.is_valid
        assert len(out.pii_fields_detected) == 2
        assert out.risk_score > 0.0


# ─── 6. Memorystore Connection Auditor Tests ─────────────────────────────────


class TestPiMemorystoreConnectionAuditor:
    def _agent(self):
        return PiMemorystoreConnectionAuditor()

    def test_valid_tls_connection(self):
        out = self._agent().execute(
            MemorystoreConnectionInput(
                connection_string="rediss://my-redis-host:6380", require_tls=True, deployment_env="production"
            )
        )
        assert out.is_valid
        assert out.uses_tls
        assert out.port == 6380
        assert out.status == "PASS"

    def test_non_tls_prod_fail(self):
        out = self._agent().execute(
            MemorystoreConnectionInput(
                connection_string="redis://my-redis-host:6379", require_tls=True, deployment_env="production"
            )
        )
        assert out.is_valid
        assert not out.uses_tls
        assert out.status in ["WARN", "FAIL"]


# ─── 7. Cloud Run Config Auditor Tests ───────────────────────────────────────


class TestPiCloudRunConfigAuditor:
    def _agent(self):
        return PiCloudRunConfigAuditor()

    def test_secure_config(self):
        yaml_content = """
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: secure-service
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/vpc-access-connector: my-connector
    spec:
      containers:
      - image: gcr.io/my-project/my-image:v1.0.0
        resources:
          limits:
            memory: 512Mi
            cpu: 1000m
        livenessProbe:
          httpGet:
            path: /healthz
        securityContext:
          runAsNonRoot: true
        env:
        - name: API_SECRET
          valueFrom:
            secretKeyRef:
              name: my-secret
              key: latest
"""
        out = self._agent().execute(CloudRunConfigInput(service_yaml=yaml_content))
        assert out.is_secure
        assert out.status == "PASS"

    def test_insecure_missing_probes_and_vpc(self):
        yaml_content = """
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: insecure-service
spec:
  template:
    spec:
      containers:
      - image: gcr.io/my-project/my-image:latest
"""
        out = self._agent().execute(CloudRunConfigInput(service_yaml=yaml_content))
        assert not out.is_secure
        assert out.status in ["WARN", "FAIL"]


# ─── 8. Workload Identity Auditor Tests ──────────────────────────────────────


class TestPiGCPWorkloadIdentityAuditor:
    def _agent(self):
        return PiGCPWorkloadIdentityAuditor()

    def test_compliant_workload(self):
        out = self._agent().execute(
            WorkloadIdentityInput(
                uses_service_account_key_file=False,
                has_workload_identity_binding=True,
                service_account_email="workload-sa@my-project.iam.gserviceaccount.com",
                deployment_target="gke",
            )
        )
        assert out.is_compliant
        assert out.status == "PASS"

    def test_non_compliant_key_file_used(self):
        out = self._agent().execute(
            WorkloadIdentityInput(
                uses_service_account_key_file=True,
                has_workload_identity_binding=False,
                service_account_email="workload-sa@my-project.iam.gserviceaccount.com",
                deployment_target="gke",
            )
        )
        assert not out.is_compliant
        assert out.status == "FAIL"


# ─── 9. GCP IAM Policy Risk Auditor Tests ────────────────────────────────────


class TestPiGCPIAMPolicyRiskAuditor:
    def _agent(self):
        return PiGCPIAMPolicyRiskAuditor()

    def test_secure_policy(self):
        policy = {"bindings": [{"role": "roles/viewer", "members": ["user:alice@example.com"]}]}
        out = self._agent().execute(GCPIAMPolicyInput(policy_json=json.dumps(policy), risk_tolerance="medium"))
        assert out.is_secure
        assert out.status == "PASS"

    def test_public_privileged_binding(self):
        policy = {"bindings": [{"role": "roles/owner", "members": ["allUsers"]}]}
        out = self._agent().execute(GCPIAMPolicyInput(policy_json=json.dumps(policy), risk_tolerance="low"))
        assert not out.is_secure
        assert out.status == "FAIL"


# ─── 10. GCP VPC Connector Validator Tests ───────────────────────────────────


class TestPiGCPVPCConnectorValidator:
    def _agent(self):
        return PiGCPVPCConnectorValidator()

    def test_valid_connector(self):
        out = self._agent().execute(
            VPCConnectorInput(connector_name="my-vpc-connector", ip_cidr_range="10.8.0.0/28", network="default")
        )
        assert out.is_valid
        assert out.status == "PASS"

    def test_invalid_cidr_or_name(self):
        out = self._agent().execute(
            VPCConnectorInput(connector_name="UPPERCASE-NOT-ALLOWED", ip_cidr_range="10.8.0.0/24", network="default")
        )
        assert not out.is_valid
        assert out.status == "FAIL"
