"""Stateful parity harness for the event bus (pi_event_fabric.bus.core).

Drives an identical operation sequence against the original Python
EventBusStorage and the Rust pi_core.EventBus, feeding BOTH the same injected
clock (timestamp / ordering_key / created_at). Because the original
DeterministicClock actually reads wall-clock time, we control time on the
Python side via a duck-typed FakeClock + a frozen `datetime` in the core module;
the Rust port takes the marker directly. Then we compare, byte-for-byte:

  - each appended event (header + payload + sha256 event_hash)
  - read_partition / read_event / read_by_correlation / get_partition_tail
  - tenant-filtered reads
  - get_partition_metadata, get_stats
  - verify_partition_chain (cryptographic chain integrity)
  - checkpoint write/read (incl. checkpoint_hash)

Run:  PYTHONPATH=.:../../src python event_fabric_parity.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

import pi_event_fabric.bus.core as core  # noqa: E402
from pi_event_fabric.bus.core import ConsumerCheckpoint, EventBusStorage, EventType  # noqa: E402
from pi_interoperability_layer.snapshot.clock import TimestampMarker, canonical_timestamp  # noqa: E402
import pi_core  # noqa: E402

# ── Freeze the non-deterministic bits of the Python original ────────────────
FIXED_CREATED = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
FIXED_CREATED_ISO = FIXED_CREATED.isoformat()


class _FrozenDatetime:
    """Replaces `datetime` in core so `datetime.now(tz).isoformat()` (the
    partition created_at) is deterministic."""
    @staticmethod
    def now(tz=None):
        return FIXED_CREATED


core.datetime = _FrozenDatetime


class FakeClock:
    """Duck-typed clock: append() only calls .ordered_now()."""
    def __init__(self, marker):
        self._m = marker

    def ordered_now(self):
        return self._m


def make_marker(seq: int, micro: int) -> TimestampMarker:
    wall = datetime(2026, 1, 1, 0, 0, 0, micro, tzinfo=timezone.utc)
    return TimestampMarker(wall_time=wall, sequence_number=seq, clock_id="eventbus")


# ── Operation sequence (diverse payloads incl. unicode/control/nested) ──────
# (event_type_value, partition, payload, tenant, actor, correlation, seq, micro)
OPS = [
    ("artifact:created", "default", {"name": "a", "n": 1}, "t1", "act1", "corrA", 1, 1000),
    ("artifact:created", "default", {"name": "b", "nested": {"z": 1, "a": [3, 2, 1]}}, "t1", "act1", "corrA", 1, 2000),
    ("worker:dispatched", "workers", {"unicode": "café ☃ \U0001f600", "ctrl": "x\ty\nz"}, "t2", "act2", "corrB", 1, 3000),
    ("worker:completed", "workers", {"ok": True, "none": None, "empty": {}, "list": []}, "t2", "act2", "corrB", 1, 4000),
    ("policy:enforced", "governance", {"rule": "R1", "big": 12345678901234567890}, "t1", "act3", "corrA", 1, 5000),
    ("artifact:created", "default", {"name": "c", "k": "v"}, "t3", "act4", "corrC", 1, 6000),
    ("worker:failed", "workers", {"err": "boom", "code": -7}, "t1", "act1", "corrB", 1, 7000),
]

CHECK_PARTITIONS = ["default", "workers", "governance", "missing_partition"]
CHECK_CORR = ["corrA", "corrB", "corrC", "nope"]

mismatches = []


def cmp(label, a, b):
    if a != b:
        mismatches.append((label, a, b))


def main():
    py_db = tempfile.mktemp(suffix=".db")
    rs_db = tempfile.mktemp(suffix=".db")
    pst = EventBusStorage(py_db)
    rbus = pi_core.EventBus(rs_db)

    last_event_in_partition = {}

    for i, (et, pk, payload, tenant, actor, corr, seq, micro) in enumerate(OPS):
        marker = make_marker(seq, micro)
        ts = canonical_timestamp(marker.wall_time)
        ordering_key = marker.ordering_key

        pev = pst.append(EventType(et), pk, payload, tenant, actor, corr, clock=FakeClock(marker))
        py = pev.serialize()
        rs = json.loads(
            rbus.append(et, pk, json.dumps(payload), tenant, actor, corr, ts, ordering_key, FIXED_CREATED_ISO)
        )
        cmp(f"append[{i}] {et}/{pk}", py, rs)
        last_event_in_partition[pk] = pev.header.event_id

    # reads per partition
    for pk in CHECK_PARTITIONS:
        py_list = [e.serialize() for e in pst.read_partition(pk, 1, 1000)]
        rs_list = json.loads(rbus.read_partition(pk, 1, 1000))
        cmp(f"read_partition[{pk}]", py_list, rs_list)

        py_tail = [e.serialize() for e in pst.get_partition_tail(pk, 3)]
        rs_tail = json.loads(rbus.get_partition_tail(pk, 3))
        cmp(f"get_partition_tail[{pk}]", py_tail, rs_tail)

        py_meta = pst.get_partition_metadata(pk)
        rs_meta_raw = rbus.get_partition_metadata(pk)
        rs_meta = json.loads(rs_meta_raw) if rs_meta_raw is not None else None
        cmp(f"get_partition_metadata[{pk}]", py_meta, rs_meta)

        py_ok, py_errs = pst.verify_partition_chain(pk)
        rs_chain = json.loads(rbus.verify_partition_chain(pk))
        cmp(f"verify_partition_chain[{pk}]", {"ok": py_ok, "errors": py_errs}, rs_chain)

    # tenant-filtered read
    py_t = [e.serialize() for e in pst.read_partition("default", 1, 1000, tenant_filter="t1")]
    rs_t = json.loads(rbus.read_partition("default", 1, 1000, "t1"))
    cmp("read_partition[default|tenant=t1]", py_t, rs_t)

    # read_by_correlation
    for corr in CHECK_CORR:
        py_c = [e.serialize() for e in pst.read_by_correlation(corr)]
        rs_c = json.loads(rbus.read_by_correlation(corr))
        cmp(f"read_by_correlation[{corr}]", py_c, rs_c)

    # read_event (hit + miss)
    some_id = last_event_in_partition["default"]
    cmp("read_event[hit]", pst.read_event(some_id).serialize(), json.loads(rbus.read_event(some_id)))
    cmp("read_event[miss]", pst.read_event("nope"), rbus.read_event("nope"))

    # stats
    cmp("get_stats", pst.get_stats(), json.loads(rbus.get_stats()))

    # checkpoints (write + read, incl. checkpoint_hash)
    for pk in ["default", "workers"]:
        lid = last_event_in_partition[pk]
        cp = ConsumerCheckpoint(
            consumer_id="consumer1", partition_key=pk,
            last_consumed_offset=2, last_event_id=lid,
            checkpoint_hash="", checkpointed_at=FIXED_CREATED_ISO,
        )
        object.__setattr__(cp, "checkpoint_hash", cp._compute_hash())
        pst.write_checkpoint(cp)
        pcp = pst.read_checkpoint("consumer1", pk)
        py_cp = {
            "consumer_id": pcp.consumer_id, "partition_key": pcp.partition_key,
            "last_consumed_offset": pcp.last_consumed_offset, "last_event_id": pcp.last_event_id,
            "checkpoint_hash": pcp.checkpoint_hash, "checkpointed_at": pcp.checkpointed_at,
        }
        rs_cp = json.loads(rbus.write_checkpoint("consumer1", pk, 2, lid, FIXED_CREATED_ISO))
        cmp(f"checkpoint_write[{pk}]", py_cp, rs_cp)
        rs_cp_read = json.loads(rbus.read_checkpoint("consumer1", pk))
        cmp(f"checkpoint_read[{pk}]", py_cp, rs_cp_read)

    os.remove(py_db)
    os.remove(rs_db)

    total = "events + reads + chain + meta + stats + checkpoints"
    if mismatches:
        print(f"EVENT-FABRIC PARITY: {len(mismatches)} MISMATCH(es)\n")
        for label, a, b in mismatches[:12]:
            print(f"  [{label}]\n    python: {a}\n    rust:   {b}\n")
        sys.exit(1)
    print(f"EVENT-FABRIC PARITY: ALL MATCH ({total}) — byte-identical, incl. SHA-256 hashes/chains")


if __name__ == "__main__":
    main()
