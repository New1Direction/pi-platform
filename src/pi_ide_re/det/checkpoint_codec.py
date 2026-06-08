"""
checkpoint_codec.py - marker-based state serialization (Theme 4, P2).

Borrowed from Kabukiskills/state_machine/serialization.py (pack/unpack state
into JSON markers) and made content-addressed: every packed state carries a
``state_hash`` so a resume can detect tampering/divergence (the same safety idea
as orchestrator/checkpoint.py's goal_hash). Applied to ``Campaign`` for
pause/resume/replay.

Deterministic: state is canonicalized before serialization, so the same logical
state always packs to identical bytes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Union

from ..graph_schema import KnowledgeGraph, _canonical, content_hash

MARKER = "__pi_re_checkpoint__"


class CheckpointMismatch(RuntimeError):
    """Raised when a packed state's state_hash != the hash of its payload."""


def pack_state(state: Dict[str, Any]) -> str:
    canon = _canonical(state)
    return json.dumps(
        {MARKER: True, "state": canon, "state_hash": content_hash(state)},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def is_checkpoint_marker(content: str) -> bool:
    try:
        doc = json.loads(content)
    except Exception:
        return False
    return isinstance(doc, dict) and doc.get(MARKER) is True


def unpack_state(content: str) -> Optional[Dict[str, Any]]:
    """Return the state dict if `content` is a valid checkpoint, else None.

    Raises CheckpointMismatch if the embedded state_hash does not match.
    """
    if not is_checkpoint_marker(content):
        return None
    doc = json.loads(content)
    state = doc.get("state", {})
    if doc.get("state_hash") != content_hash(state):
        raise CheckpointMismatch("checkpoint state_hash mismatch - state was tampered with or corrupted")
    return state


# ---- campaign pause / resume / replay ----------------------------------


def pack_campaign(campaign) -> str:
    state = {
        "target": campaign.target,
        "graph": campaign.graph.model_dump(mode="json"),
        "records": [vars(r) for r in campaign.records],
        "transitions": campaign.transitions,
    }
    return pack_state(state)


def restore_campaign(content: str, root: Union[str, Path] = "re"):
    from ..playbook import Campaign, PhaseRecord  # local import to avoid cycle

    state = unpack_state(content)
    if state is None:
        raise CheckpointMismatch("content is not a pi-re checkpoint")
    campaign = Campaign(state["target"], root=root)
    campaign.graph = KnowledgeGraph.model_validate(state["graph"])
    campaign.records = [PhaseRecord(**r) for r in state.get("records", [])]
    campaign.transitions = list(state.get("transitions", []))
    return campaign
