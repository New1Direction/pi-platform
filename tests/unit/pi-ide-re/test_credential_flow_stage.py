"""
Tests for the auth/credential-flow stage (Theme 1, P2). RE use only.

Adapts the credential-dumper / ssl-pinning-bypass Frida scripts for IDE auth
(OAuth / session tokens / API keys). The non-negotiable invariant: raw secret
VALUES never enter the graph. We store key names + a one-way fingerprint so the
same secret can be correlated across sources without ever persisting it.
"""

from __future__ import annotations

import json

from pi_ide_re.stages import credential_flow as cf

CAPTURE = {
    "target": "Antigravity Helper",
    "ssl_pinning_bypassed": True,
    "credentials": [
        {"source": "keychain", "key": "com.google.gemini/access_token", "value": "ya29.SUPERSECRET", "type": "oauth"},
        {"source": "nsuserdefaults", "key": "session.id", "value": "sess_DEADBEEF", "type": "session"},
        {"source": "env", "key": "GEMINI_API_KEY", "value": "AIzaTOPSECRET", "type": "api_key"},
    ],
}


class TestRedaction:
    def test_redact_hides_value_but_is_deterministic(self):
        a = cf.redact_secret("hunter2")
        b = cf.redact_secret("hunter2")
        assert a == b
        assert "hunter2" not in a
        assert a.startswith("<redacted:")

    def test_redact_empty(self):
        assert cf.redact_secret("") == "<empty>"
        assert cf.redact_secret(None) == "<empty>"

    def test_different_secret_different_fingerprint(self):
        assert cf.redact_secret("a") != cf.redact_secret("b")


class TestIngest:
    def test_no_raw_secret_value_anywhere_in_graph(self):
        result = cf.CredentialFlowStage().ingest(CAPTURE)
        blob = json.dumps([n.model_dump(mode="json") for n in result.nodes])
        for secret in ["ya29.SUPERSECRET", "sess_DEADBEEF", "AIzaTOPSECRET"]:
            assert secret not in blob

    def test_key_names_retained(self):
        result = cf.CredentialFlowStage().ingest(CAPTURE)
        blob = json.dumps([n.model_dump(mode="json") for n in result.nodes])
        assert "GEMINI_API_KEY" in blob
        assert "session.id" in blob

    def test_produces_credential_traces_and_a_risk_node(self):
        result = cf.CredentialFlowStage().ingest(CAPTURE)
        cred_nodes = [n for n in result.nodes if n.type == "dynamic-trace" and "credential:" in n.title]
        assert len(cred_nodes) == 3
        assert any(n.type == "risk" for n in result.nodes)

    def test_summary_reports_ssl_and_counts(self):
        result = cf.CredentialFlowStage().ingest(CAPTURE)
        assert result.summary["ssl_pinning_bypassed"] is True
        assert result.summary["credentials"] == 3
        assert result.summary["by_type"]["oauth"] == 1

    def test_determinism(self):
        a = sorted(n.id for n in cf.CredentialFlowStage().ingest(CAPTURE).nodes)
        b = sorted(n.id for n in cf.CredentialFlowStage().ingest(CAPTURE).nodes)
        assert a == b

    def test_same_secret_same_node_rotated_secret_differs(self):
        one = {"target": "T", "credentials": [{"source": "env", "key": "K", "value": "v1", "type": "api_key"}]}
        two = {"target": "T", "credentials": [{"source": "env", "key": "K", "value": "v2", "type": "api_key"}]}
        id1 = next(n.id for n in cf.CredentialFlowStage().ingest(one).nodes if n.type == "dynamic-trace")
        id1b = next(n.id for n in cf.CredentialFlowStage().ingest(one).nodes if n.type == "dynamic-trace")
        id2 = next(n.id for n in cf.CredentialFlowStage().ingest(two).nodes if n.type == "dynamic-trace")
        assert id1 == id1b
        assert id1 != id2


class TestBundledScripts:
    def test_bundled_scripts_available(self):
        scripts = cf.CredentialFlowStage().bundled_scripts()
        assert "credential-dumper" in scripts
        assert "ssl-pinning-bypass" in scripts
        # the scripts are real JS source, not empty
        assert "Interceptor" in cf.CredentialFlowStage().load_script("credential-dumper")
