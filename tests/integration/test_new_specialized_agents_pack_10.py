"""Integration tests for the 10 additional highly specialized dual-use PI micro-agents (Cohort 10: Agents 101-110)."""

from __future__ import annotations

import os
import pytest

from pi_micro_agents import (
    PiGitSecretEntropyLeakSentry,
    GitSecretEntropyLeakInput,
    PiDockerComposePortExposureSentry,
    DockerComposePortExposureInput,
    PiGithubActionsUnpinnedVersion,
    GithubActionsUnpinnedInput,
    PiTerraformStateCredentialSentry,
    TerraformStateCredentialInput,
    PiNginxReverseProxyHeaderSentry,
    NginxReverseProxyHeaderInput,
    PiDatabaseMigrationUnindexedSentry,
    DatabaseMigrationUnindexedInput,
    PiApiAuthJWTNoneAlgorithmSentry,
    ApiAuthJWTNoneAlgorithmInput,
    PiSemanticSchemaDynamicFieldCheck,
    SemanticSchemaDynamicFieldInput,
    PiApiAuthHardcodedTokenSentry,
    ApiAuthHardcodedTokenInput,
    PiGrpcWireProtocolInsecureSentry,
    GrpcWireProtocolInsecureInput,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean test environment variables before each test runs."""
    monkeypatch.delenv("PI_GIT_SECRET_ENTROPY_LEAK_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_DOCKER_COMPOSE_PORT_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_GITHUB_ACTIONS_UNPINNED_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_TERRAFORM_STATE_CREDENTIAL_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_NGINX_REVERSE_PROXY_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_DATABASE_MIGRATION_UNINDEXED_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_API_AUTH_JWT_NONE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_SEMANTIC_SCHEMA_DYNAMIC_FIELD_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_API_AUTH_HARDCODED_TOKEN_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_GRPC_WIRE_PROTOCOL_INSECURE_STRICT_MODE", raising=False)


# =====================================================================
# 101. PiGitSecretEntropyLeakSentry Verification
# =====================================================================
def test_git_secret_entropy_leak_sentry(monkeypatch):
    agent = PiGitSecretEntropyLeakSentry()

    # Quoted string of length >= 16 with unique characters has entropy > 4.5
    code_vuln = 'token = "gZ7xP9qW3hK2vL4mY6tB1sN8"'
    res_vuln = agent.audit_entropy_leaks(GitSecretEntropyLeakInput(file_path="app.py", code_content=code_vuln))
    assert not res_vuln.is_secure
    assert "gZ7xP9qW3h" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_GIT_SECRET_ENTROPY_LEAK"

    monkeypatch.setenv("PI_GIT_SECRET_ENTROPY_LEAK_STRICT_MODE", "false")
    res_warn = agent.audit_entropy_leaks(GitSecretEntropyLeakInput(file_path="app.py", code_content=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_GIT_SECRET_ENTROPY_LEAK"

    code_safe = 'token = "shortpass"'
    res_safe = agent.audit_entropy_leaks(GitSecretEntropyLeakInput(file_path="app.py", code_content=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 102. PiDockerComposePortExposureSentry Verification
# =====================================================================
def test_docker_compose_port_exposure_sentry(monkeypatch):
    agent = PiDockerComposePortExposureSentry()

    code_vuln = """
    services:
      db:
        image: mysql:8.0
        ports:
          - "3306:3306"
    """
    res_vuln = agent.audit_docker_compose_ports(DockerComposePortExposureInput(file_path="docker-compose.yml", compose_code=code_vuln))
    assert not res_vuln.is_secure
    assert "db" in res_vuln.vulnerable_services
    assert res_vuln.status == "REJECTED_DOCKER_COMPOSE_PORT"

    monkeypatch.setenv("PI_DOCKER_COMPOSE_PORT_STRICT_MODE", "false")
    res_warn = agent.audit_docker_compose_ports(DockerComposePortExposureInput(file_path="docker-compose.yml", compose_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_DOCKER_COMPOSE_PORT"

    code_safe = """
    services:
      db:
        image: mysql:8.0
        ports:
          - "127.0.0.1:3306:3306"
    """
    res_safe = agent.audit_docker_compose_ports(DockerComposePortExposureInput(file_path="docker-compose.yml", compose_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 103. PiGithubActionsUnpinnedVersion Verification
# =====================================================================
def test_github_actions_unpinned_version(monkeypatch):
    agent = PiGithubActionsUnpinnedVersion()

    code_vuln = """
    name: Build
    jobs:
      test:
        steps:
          - uses: actions/checkout@v3
    """
    res_vuln = agent.audit_github_actions(GithubActionsUnpinnedInput(file_path="workflow.yml", yaml_code=code_vuln))
    assert not res_vuln.is_secure
    assert "Line 6" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_GITHUB_ACTIONS_UNPINNED"

    monkeypatch.setenv("PI_GITHUB_ACTIONS_UNPINNED_STRICT_MODE", "false")
    res_warn = agent.audit_github_actions(GithubActionsUnpinnedInput(file_path="workflow.yml", yaml_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_GITHUB_ACTIONS_UNPINNED"

    code_safe = """
    name: Build
    jobs:
      test:
        steps:
          - uses: actions/checkout@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2
    """
    res_safe = agent.audit_github_actions(GithubActionsUnpinnedInput(file_path="workflow.yml", yaml_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 104. PiTerraformStateCredentialSentry Verification
# =====================================================================
def test_terraform_state_credential_sentry(monkeypatch):
    agent = PiTerraformStateCredentialSentry()

    code_vuln = """
    provider "aws" {
      region     = "us-west-2"
      secret_key = "my-secret-key-value-123"
    }
    """
    res_vuln = agent.audit_terraform_credentials(TerraformStateCredentialInput(file_path="main.tf", tf_code=code_vuln))
    assert not res_vuln.is_secure
    assert "Line 4" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_TERRAFORM_STATE_CREDENTIAL"

    monkeypatch.setenv("PI_TERRAFORM_STATE_CREDENTIAL_STRICT_MODE", "false")
    res_warn = agent.audit_terraform_credentials(TerraformStateCredentialInput(file_path="main.tf", tf_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_TERRAFORM_STATE_CREDENTIAL"

    code_safe = """
    provider "aws" {
      region     = "us-west-2"
      secret_key = var.my_secret_key
    }
    """
    res_safe = agent.audit_terraform_credentials(TerraformStateCredentialInput(file_path="main.tf", tf_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 105. PiNginxReverseProxyHeaderSentry Verification
# =====================================================================
def test_nginx_reverse_proxy_header_sentry(monkeypatch):
    agent = PiNginxReverseProxyHeaderSentry()

    code_vuln = """
    server {
        location /api {
            proxy_pass http://backend;
        }
    }
    """
    res_vuln = agent.audit_nginx_headers(NginxReverseProxyHeaderInput(file_path="nginx.conf", nginx_code=code_vuln))
    assert not res_vuln.is_secure
    assert "/api" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_NGINX_REVERSE_PROXY"

    monkeypatch.setenv("PI_NGINX_REVERSE_PROXY_STRICT_MODE", "false")
    res_warn = agent.audit_nginx_headers(NginxReverseProxyHeaderInput(file_path="nginx.conf", nginx_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_NGINX_REVERSE_PROXY"

    code_safe = """
    server {
        location /api {
            proxy_pass http://backend;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }
    """
    res_safe = agent.audit_nginx_headers(NginxReverseProxyHeaderInput(file_path="nginx.conf", nginx_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 106. PiDatabaseMigrationUnindexedSentry Verification
# =====================================================================
def test_database_migration_unindexed_sentry(monkeypatch):
    agent = PiDatabaseMigrationUnindexedSentry()

    code_vuln = """
    CREATE TABLE users (
        id INT PRIMARY KEY,
        tenant_id INT
    );
    """
    res_vuln = agent.audit_migration_indexes(DatabaseMigrationUnindexedInput(file_path="migration.sql", migration_code=code_vuln))
    assert not res_vuln.is_secure
    assert "Line 4" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_DATABASE_MIGRATION_UNINDEXED"

    monkeypatch.setenv("PI_DATABASE_MIGRATION_UNINDEXED_STRICT_MODE", "false")
    res_warn = agent.audit_migration_indexes(DatabaseMigrationUnindexedInput(file_path="migration.sql", migration_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_DATABASE_MIGRATION_UNINDEXED"

    code_safe = """
    CREATE TABLE users (
        id INT PRIMARY KEY,
        tenant_id INT
    );
    CREATE INDEX idx_users_tenant ON users(tenant_id);
    """
    res_safe = agent.audit_migration_indexes(DatabaseMigrationUnindexedInput(file_path="migration.sql", migration_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 107. PiApiAuthJWTNoneAlgorithmSentry Verification
# =====================================================================
def test_api_auth_jwt_none_algorithm_sentry(monkeypatch):
    agent = PiApiAuthJWTNoneAlgorithmSentry()

    code_vuln = """
    def decode_token(token):
        return jwt.decode(token, verify=False)
    """
    res_vuln = agent.audit_jwt_none_algorithm(ApiAuthJWTNoneAlgorithmInput(file_path="auth.py", code_content=code_vuln))
    assert not res_vuln.is_secure
    assert "Line 3" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_API_AUTH_JWT_NONE"

    monkeypatch.setenv("PI_API_AUTH_JWT_NONE_STRICT_MODE", "false")
    res_warn = agent.audit_jwt_none_algorithm(ApiAuthJWTNoneAlgorithmInput(file_path="auth.py", code_content=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_API_AUTH_JWT_NONE"

    code_safe = """
    def decode_token(token):
        return jwt.decode(token, algorithms=["HS256"])
    """
    res_safe = agent.audit_jwt_none_algorithm(ApiAuthJWTNoneAlgorithmInput(file_path="auth.py", code_content=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 108. PiSemanticSchemaDynamicFieldCheck Verification
# =====================================================================
def test_semantic_schema_dynamic_field_check(monkeypatch):
    agent = PiSemanticSchemaDynamicFieldCheck()

    code_vuln = """
    class User(Base):
        __tablename__ = 'users'
        metadata = Column(JSON)
    """
    res_vuln = agent.audit_dynamic_fields(SemanticSchemaDynamicFieldInput(file_path="models.py", schema_code=code_vuln))
    assert not res_vuln.is_secure
    assert "metadata" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_SEMANTIC_SCHEMA_DYNAMIC_FIELD"

    monkeypatch.setenv("PI_SEMANTIC_SCHEMA_DYNAMIC_FIELD_STRICT_MODE", "false")
    res_warn = agent.audit_dynamic_fields(SemanticSchemaDynamicFieldInput(file_path="models.py", schema_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_SEMANTIC_SCHEMA_DYNAMIC_FIELD"

    code_safe = """
    class User(Base):
        __tablename__ = 'users'
        metadata = Column(JSON)
        metadata_schema = UserMetadataSchema()
    """
    res_safe = agent.audit_dynamic_fields(SemanticSchemaDynamicFieldInput(file_path="models.py", schema_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 109. PiApiAuthHardcodedTokenSentry Verification
# =====================================================================
def test_api_auth_hardcoded_token_sentry(monkeypatch):
    agent = PiApiAuthHardcodedTokenSentry()

    code_vuln = """
    def authenticate():
        api_key = "my-secret-static-token-value"
    """
    res_vuln = agent.audit_hardcoded_tokens(ApiAuthHardcodedTokenInput(file_path="auth.py", code_content=code_vuln))
    assert not res_vuln.is_secure
    assert "Line 3" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_API_AUTH_HARDCODED_TOKEN"

    monkeypatch.setenv("PI_API_AUTH_HARDCODED_TOKEN_STRICT_MODE", "false")
    res_warn = agent.audit_hardcoded_tokens(ApiAuthHardcodedTokenInput(file_path="auth.py", code_content=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_API_AUTH_HARDCODED_TOKEN"

    code_safe = """
    def authenticate():
        api_key = os.getenv("API_KEY")
    """
    res_safe = agent.audit_hardcoded_tokens(ApiAuthHardcodedTokenInput(file_path="auth.py", code_content=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 110. PiGrpcWireProtocolInsecureSentry Verification
# =====================================================================
def test_grpc_wire_protocol_insecure_sentry(monkeypatch):
    agent = PiGrpcWireProtocolInsecureSentry()

    code_vuln = """
    channel = grpc.insecure_channel('localhost:50051')
    """
    res_vuln = agent.audit_grpc_insecure(GrpcWireProtocolInsecureInput(file_path="client.py", code_content=code_vuln))
    assert not res_vuln.is_secure
    assert "Line 2" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_GRPC_WIRE_PROTOCOL_INSECURE"

    monkeypatch.setenv("PI_GRPC_WIRE_PROTOCOL_INSECURE_STRICT_MODE", "false")
    res_warn = agent.audit_grpc_insecure(GrpcWireProtocolInsecureInput(file_path="client.py", code_content=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_GRPC_WIRE_PROTOCOL_INSECURE"

    code_safe = """
    channel = grpc.secure_channel('localhost:50051', credentials)
    """
    res_safe = agent.audit_grpc_insecure(GrpcWireProtocolInsecureInput(file_path="client.py", code_content=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"
