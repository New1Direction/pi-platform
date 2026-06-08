"""The content-addressed event hash must be stable across processes.

Finding: `json.dumps(payload, sort_keys=True, default=str)` only orders dict KEYS;
a set value falls to `str(set)`, whose order depends on PYTHONHASHSEED, so the
same logical event hashed differently across runs — breaking replay/chain
verification for any set-bearing payload.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[3]

# Build a real DomainEvent with a set in the payload and print its event_hash.
_SNIPPET = (
    "import sys; sys.path.insert(0, 'src');"
    "from pi_event_fabric.bus.core import DomainEvent, EventHeader, EventType;"
    "h = EventHeader(event_id='e', event_type=EventType.WORKER_COMPLETED, partition_key='p',"
    " partition_offset=1, timestamp='t', ordering_key='o', author_tenant_id='ten',"
    " author_actor_id='a', correlation_id='c', previous_event_hash='', payload_hash='ph');"
    "ev = DomainEvent(header=h, payload={'agents': {'z', 'a', 'm', 'q', 'b', 'x'}});"
    "print(ev.event_hash)"
)


def _hash_under_seed(seed: int) -> str:
    out = subprocess.run(
        [sys.executable, "-c", _SNIPPET],
        cwd=str(_REPO),
        env={"PYTHONHASHSEED": str(seed), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def test_set_bearing_event_hash_is_stable_across_hash_seeds():
    hashes = {_hash_under_seed(seed) for seed in (0, 1, 2, 3)}
    assert len(hashes) == 1, f"event_hash varied with PYTHONHASHSEED: {hashes}"
