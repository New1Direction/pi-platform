"""
Tests for the RE artifact store: content-addressed payload archival under
re/<target>/ with a deterministic .index.json manifest and provenance sidecars.

Invariants:
- identical payloads dedupe (same content hash key, idempotent re-store)
- the manifest is stable/sorted and reloadable
- provenance (captured_at) is recorded but never affects the content hash/key
- json payloads are canonicalized so logically-equal dicts dedupe
"""

from __future__ import annotations

import json

from pi_ide_re.artifacts import ArtifactStore


class TestArtifactStore:
    def test_store_text_returns_ref_and_writes_file(self, tmp_path):
        store = ArtifactStore(root=tmp_path, target="acme-ide")
        ref = store.store_payload("static", "ghidra", "strings.txt", "hello world", kind="text")
        assert ref.path.exists()
        assert ref.phase == "static"
        assert ref.agent == "ghidra"
        assert ref.content_hash
        assert ref.path.read_text() == "hello world"
        # lives under re/<target>/payloads/<phase>/
        assert "acme-ide" in str(ref.path)
        assert "static" in str(ref.path)

    def test_identical_payload_is_idempotent(self, tmp_path):
        store = ArtifactStore(root=tmp_path, target="t")
        r1 = store.store_payload("p", "a", "n.txt", "same", kind="text", captured_at="2026-01-01T00:00:00Z")
        r2 = store.store_payload("p", "a", "n.txt", "same", kind="text", captured_at="2026-09-09T00:00:00Z")
        assert r1.content_hash == r2.content_hash
        assert r1.path == r2.path
        manifest = store.manifest()
        assert len(manifest["artifacts"]) == 1

    def test_provenance_recorded_but_not_in_hash(self, tmp_path):
        store = ArtifactStore(root=tmp_path, target="t")
        ref = store.store_payload("p", "a", "n.txt", "x", kind="text", captured_at="2026-06-01T12:00:00Z")
        entry = store.manifest()["artifacts"][ref.content_hash]
        assert entry["captured_at"] == "2026-06-01T12:00:00Z"
        assert entry["phase"] == "p"
        assert entry["agent"] == "a"

    def test_json_payload_canonicalized_so_equal_dicts_dedupe(self, tmp_path):
        store = ArtifactStore(root=tmp_path, target="t")
        r1 = store.store_payload("p", "a", "d.json", {"b": 2, "a": 1}, kind="json")
        r2 = store.store_payload("p", "a", "d.json", {"a": 1, "b": 2}, kind="json")
        assert r1.content_hash == r2.content_hash
        assert len(store.manifest()["artifacts"]) == 1

    def test_different_content_distinct_entries(self, tmp_path):
        store = ArtifactStore(root=tmp_path, target="t")
        store.store_payload("p", "a", "n.txt", "one", kind="text")
        store.store_payload("p", "a", "n.txt", "two", kind="text")
        assert len(store.manifest()["artifacts"]) == 2

    def test_manifest_persisted_and_reloadable(self, tmp_path):
        store = ArtifactStore(root=tmp_path, target="t")
        ref = store.store_payload("p", "a", "n.txt", "data", kind="text")
        # fresh store over same root sees the persisted manifest
        store2 = ArtifactStore(root=tmp_path, target="t")
        assert ref.content_hash in store2.manifest()["artifacts"]

    def test_manifest_file_is_sorted_json(self, tmp_path):
        store = ArtifactStore(root=tmp_path, target="t")
        store.store_payload("p", "a", "n.txt", "zzz", kind="text")
        store.store_payload("p", "a", "n.txt", "aaa", kind="text")
        index_file = store.index_path
        assert index_file.exists()
        raw = index_file.read_text()
        # round-trips and keys are sorted
        data = json.loads(raw)
        keys = list(data["artifacts"].keys())
        assert keys == sorted(keys)
