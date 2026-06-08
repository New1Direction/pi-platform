"""
Tests for the dynamic-RE extensions to the typed knowledge graph schema.

Core invariant under test: the graph is CONTENT-ADDRESSED and DETERMINISTIC.
Re-ingesting the same captured artifact must yield the same node id, and
volatile capture metadata (pid, timestamps, ports, load addresses) must NOT
affect node identity. This mirrors the platform's compute_hash discipline
(wall-clock / resource fields excluded from the hash).
"""

from __future__ import annotations

import pytest

from pi_ide_re.graph_schema import (
    BinaryString,
    CapturedRequest,
    DynamicTrace,
    FunctionInterest,
    GraphNode,
    KnowledgeGraph,
    NodeMetadata,
    ProcessHook,
    content_hash,
    save_knowledge_graph,
)


class TestContentHash:
    def test_deterministic_and_key_order_independent(self):
        a = content_hash({"b": 2, "a": 1})
        b = content_hash({"a": 1, "b": 2})
        assert a == b

    def test_sets_are_canonicalized(self):
        # set ordering must not change the hash
        a = content_hash({"vals": {"z", "a", "m"}})
        b = content_hash({"vals": {"a", "m", "z"}})
        assert a == b

    def test_excluded_keys_do_not_affect_hash(self):
        base = content_hash({"k": "v"})
        with_volatile = content_hash({"k": "v", "ts": "2026-06-01T00:00:00Z", "pid": 1234}, exclude={"ts", "pid"})
        assert base == with_volatile

    def test_different_content_differs(self):
        assert content_hash({"k": "v1"}) != content_hash({"k": "v2"})


class TestNewNodeTypes:
    @pytest.mark.parametrize(
        "node_type",
        ["dynamic-trace", "captured-request", "binary-string", "function-interest", "process-hook", "feature-flag"],
    )
    def test_new_node_types_accepted(self, node_type):
        node = GraphNode(id=f"{node_type}/x", type=node_type, title="t", content="c")
        assert node.type == node_type


class TestDynamicTrace:
    def test_node_id_is_stable_across_volatile_fields(self):
        t1 = DynamicTrace(target="LangServer", hook="objc_msgSend:tool", findings=["toolCall", "agentStep"], pid=111)
        t2 = DynamicTrace(
            target="LangServer",
            hook="objc_msgSend:tool",
            findings=["agentStep", "toolCall"],  # different order
            pid=222,  # different pid
            captured_at="2026-06-01T12:00:00Z",  # volatile
        )
        assert t1.node_id() == t2.node_id()

    def test_to_graph_node_is_content_addressed(self):
        t = DynamicTrace(target="LangServer", hook="send", findings=["x"])
        node = t.to_graph_node()
        assert node.type == "dynamic-trace"
        assert node.id == t.node_id()
        assert node.id.startswith("dynamic-trace/")

    def test_different_hook_differs(self):
        a = DynamicTrace(target="T", hook="h1", findings=[]).node_id()
        b = DynamicTrace(target="T", hook="h2", findings=[]).node_id()
        assert a != b


class TestCapturedRequest:
    def test_endpoint_identity_ignores_timestamp_and_token_values(self):
        r1 = CapturedRequest(
            method="POST",
            url="https://api.example.com/v1/chat?nonce=aaa",
            host="api.example.com",
            path="/v1/chat",
            auth_schemes=["authorization"],
            timestamp="2026-06-01T00:00:00Z",
        )
        r2 = CapturedRequest(
            method="POST",
            url="https://api.example.com/v1/chat?nonce=zzz",  # different volatile query
            host="api.example.com",
            path="/v1/chat",
            auth_schemes=["authorization"],
            timestamp="2026-06-02T00:00:00Z",  # different time
        )
        assert r1.node_id() == r2.node_id()

    def test_different_endpoint_differs(self):
        a = CapturedRequest(method="GET", url="u", host="h", path="/a", auth_schemes=[]).node_id()
        b = CapturedRequest(method="GET", url="u", host="h", path="/b", auth_schemes=[]).node_id()
        assert a != b

    def test_to_graph_node(self):
        r = CapturedRequest(method="GET", url="u", host="h", path="/p", auth_schemes=["x-api-key"])
        node = r.to_graph_node()
        assert node.type == "captured-request"
        assert node.id.startswith("captured-request/")


class TestBinaryStringAndFunctionInterest:
    def test_binary_string_identity_ignores_address(self):
        a = BinaryString(value="SandboxPolicy", context="sandbox", addr="0x1000").node_id()
        b = BinaryString(value="SandboxPolicy", context="sandbox", addr="0x9999").node_id()
        assert a == b

    def test_function_interest_identity_ignores_entry(self):
        a = FunctionInterest(name="run_agent", keywords=["agent"], entry="0x1").node_id()
        b = FunctionInterest(name="run_agent", keywords=["agent"], entry="0x2").node_id()
        assert a == b

    def test_function_interest_keyword_order_independent(self):
        a = FunctionInterest(name="f", keywords=["a", "b"]).node_id()
        b = FunctionInterest(name="f", keywords=["b", "a"]).node_id()
        assert a == b


class TestDeterministicPersistence:
    """A serialized graph must be byte-reproducible: no wall-clock leaks."""

    def test_node_metadata_last_updated_defaults_to_none(self):
        md = NodeMetadata(source_page="x")
        assert md.last_updated is None

    def test_saved_graph_is_byte_identical_across_runs(self, tmp_path):
        def build_and_save(d):
            g = KnowledgeGraph()
            for art in [
                DynamicTrace(target="T", hook="h", findings=["a", "b"]),
                CapturedRequest(method="GET", url="u", host="h", path="/p", auth_schemes=[]),
                BinaryString(value="SandboxPolicy", context="sandbox"),
            ]:
                node = art.to_graph_node()
                g.nodes[node.id] = node
            save_knowledge_graph(g, d)
            return (d / "knowledge_graph.json").read_bytes()

        d1 = tmp_path / "a"
        d2 = tmp_path / "b"
        d1.mkdir()
        d2.mkdir()
        assert build_and_save(d1) == build_and_save(d2)


class TestProcessHook:
    def test_identity_is_template_and_selector(self):
        a = ProcessHook(template="electron-objc", selector="tool", findings=["x"]).node_id()
        b = ProcessHook(template="electron-objc", selector="tool", findings=["y", "z"]).node_id()
        assert a == b  # findings are observations, not identity

    def test_to_graph_node(self):
        node = ProcessHook(template="t", selector="agent").to_graph_node()
        assert node.type == "process-hook"
