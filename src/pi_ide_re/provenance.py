"""
provenance.py - .usage.json sidecars for RE outputs (Theme 3, P3).

Every acquisition / analysis / patch artifact gets a sidecar that links it back
to the phase that produced it, the originating agent, and (optionally) the
ledger receipt - so any work product is traceable to its origin. The record is
deterministic given an explicit ``captured_at`` (the only volatile field).
Complements the ArtifactStore manifest (which records the same provenance
per-artifact); this is the per-output-file form alongside non-store outputs
like reports and patches.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Union


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sidecar_path(output_path: Union[str, Path]) -> Path:
    p = Path(output_path)
    return p.with_suffix(p.suffix + ".usage.json")


def write_usage_sidecar(
    output_path: Union[str, Path],
    *,
    phase: str,
    agent: str,
    kind: str,
    content_hash: Optional[str] = None,
    captured_at: Optional[str] = None,
    ledger_ref: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Path:
    output_path = Path(output_path)
    record = {
        "output": output_path.name,
        "phase": phase,
        "agent": agent,
        "kind": kind,
        "content_hash": content_hash,
        "captured_at": captured_at or _now_iso(),
        "ledger_ref": ledger_ref,
        "extra": extra or {},
    }
    side = _sidecar_path(output_path)
    side.parent.mkdir(parents=True, exist_ok=True)
    side.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    return side


def read_usage_sidecar(output_path: Union[str, Path]) -> Dict[str, Any]:
    return json.loads(_sidecar_path(output_path).read_text(encoding="utf-8"))
