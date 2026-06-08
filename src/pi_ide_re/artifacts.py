"""
artifacts.py - Content-addressed artifact store for RE campaigns.

Every capture stage (Frida traces, traffic HARs, Ghidra dumps, credential
scans) writes its raw payloads here. The store lays them out under
``re/<target>/payloads/<phase>/`` and maintains a deterministic
``.index.json`` manifest plus a per-artifact provenance record.

Determinism / provenance contract
----------------------------------
- Artifacts are keyed by a content hash, so identical payloads dedupe and
  re-storing is idempotent.
- JSON payloads are canonicalized (sorted keys, sets -> sorted lists) before
  hashing, so logically-equal dicts collapse to one artifact.
- ``captured_at`` and other provenance live in the manifest entry but never
  enter the content hash - the same payload captured at two different times is
  one artifact. This mirrors the platform's "strip wall-clock before hashing"
  rule (see graph_schema.content_hash and the audit's compute_hash fixes).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union

from .graph_schema import _canonical

MANIFEST_VERSION = 1

_EXT_BY_KIND = {
    "json": "json",
    "har": "har",
    "trace": "json",
    "text": "txt",
    "binary": "bin",
}


def _hash_bytes(data: bytes, length: int = 16) -> str:
    return hashlib.sha256(data).hexdigest()[:length]


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-") or "artifact"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class ArtifactRef:
    content_hash: str
    phase: str
    agent: str
    name: str
    kind: str
    size: int
    path: Path
    rel_path: str
    captured_at: str


class ArtifactStore:
    """Manages the ``re/<target>/`` work-product tree for one target."""

    def __init__(self, root: Union[str, Path], target: str):
        self.target = _safe(target)
        self.target_dir = Path(root).expanduser().resolve() / self.target
        self.payloads_dir = self.target_dir / "payloads"
        self.index_path = self.target_dir / ".index.json"
        self._manifest = self._load_manifest()

    # ---- layout helpers -------------------------------------------------

    def phase_dir(self, phase: str) -> Path:
        d = self.payloads_dir / _safe(phase)
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ---- manifest -------------------------------------------------------

    def _load_manifest(self) -> Dict[str, Any]:
        if self.index_path.exists():
            try:
                with open(self.index_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"target": self.target, "version": MANIFEST_VERSION, "artifacts": {}}

    def manifest(self) -> Dict[str, Any]:
        return self._manifest

    def _persist_manifest(self) -> None:
        self.target_dir.mkdir(parents=True, exist_ok=True)
        # sort artifact keys for a stable on-disk manifest
        artifacts = self._manifest.get("artifacts", {})
        ordered = {k: artifacts[k] for k in sorted(artifacts)}
        out = {"target": self._manifest["target"], "version": self._manifest["version"], "artifacts": ordered}
        with open(self.index_path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, sort_keys=True)

    # ---- store ----------------------------------------------------------

    def _encode(self, data: Any, kind: str) -> bytes:
        if kind in ("json", "trace", "har"):
            canonical = json.dumps(_canonical(data), sort_keys=True, separators=(",", ":"), default=str)
            return canonical.encode("utf-8")
        if isinstance(data, bytes):
            return data
        return str(data).encode("utf-8")

    def store_payload(
        self,
        phase: str,
        agent: str,
        name: str,
        data: Any,
        kind: str = "json",
        captured_at: Optional[str] = None,
    ) -> ArtifactRef:
        """Archive a payload; returns a content-addressed ref. Idempotent."""
        encoded = self._encode(data, kind)
        digest = _hash_bytes(encoded)
        ext = _EXT_BY_KIND.get(kind, "bin")
        fname = f"{_safe(agent)}__{_safe(name)}__{digest[:8]}.{ext}"
        target_path = self.phase_dir(phase) / fname
        rel_path = str(target_path.relative_to(self.target_dir))

        if digest not in self._manifest["artifacts"]:
            target_path.write_bytes(encoded)
            self._manifest["artifacts"][digest] = {
                "phase": phase,
                "agent": agent,
                "name": name,
                "kind": kind,
                "size": len(encoded),
                "rel_path": rel_path,
                "captured_at": captured_at or _now_iso(),
            }
            self._persist_manifest()

        entry = self._manifest["artifacts"][digest]
        return ArtifactRef(
            content_hash=digest,
            phase=entry["phase"],
            agent=entry["agent"],
            name=entry["name"],
            kind=entry["kind"],
            size=entry["size"],
            path=self.target_dir / entry["rel_path"],
            rel_path=entry["rel_path"],
            captured_at=entry["captured_at"],
        )

    def refs(self) -> Dict[str, ArtifactRef]:
        """All stored artifacts as refs, keyed by content hash."""
        out: Dict[str, ArtifactRef] = {}
        for digest, e in self._manifest["artifacts"].items():
            out[digest] = ArtifactRef(
                content_hash=digest,
                phase=e["phase"],
                agent=e["agent"],
                name=e["name"],
                kind=e["kind"],
                size=e["size"],
                path=self.target_dir / e["rel_path"],
                rel_path=e["rel_path"],
                captured_at=e["captured_at"],
            )
        return out

    def as_dict(self, ref: ArtifactRef) -> Dict[str, Any]:
        return asdict(ref) | {"path": str(ref.path)}
