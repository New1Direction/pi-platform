"""Randomized differential fuzzer for the event bus.

Generates random append sequences (random partitions, tenants, correlations and
deeply-random JSON payloads) against the Python and Rust buses under the same
injected clock, then compares every appended event and all read paths. This
stresses canonical-JSON hashing + SQLite ordering far beyond the curated harness.

Run:  PYTHONPATH=.:../../src python event_fabric_fuzz.py [n_ops] [--floats]
"""
from __future__ import annotations

import json
import os
import random
import sys
import tempfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

import pi_event_fabric.bus.core as core  # noqa: E402
from pi_event_fabric.bus.core import EventBusStorage, EventType  # noqa: E402
from pi_interoperability_layer.snapshot.clock import TimestampMarker, canonical_timestamp  # noqa: E402
import pi_core  # noqa: E402

FIXED_CREATED = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
FIXED_CREATED_ISO = FIXED_CREATED.isoformat()
core.datetime = type("FD", (), {"now": staticmethod(lambda tz=None: FIXED_CREATED)})


class FakeClock:
    def __init__(self, m):
        self._m = m

    def ordered_now(self):
        return self._m


EVENT_TYPES = [
    "artifact:created", "worker:dispatched", "worker:completed", "worker:failed",
    "policy:enforced", "composition:accepted", "snapshot:stored", "tenant:created",
]
PARTITIONS = ["default", "workers", "compositions", "artifacts", "audit"]
TENANTS = ["t1", "t2", "t3", "tenant-x"]
CORRS = ["corrA", "corrB", "corrC", "corrD", "corrE"]
KEYS = ["name", "id", "value", "z", "a", "m", "데이터", "k1", "k2", "nested", "list"]
STRS = ["x", "café", "☃", "a\tb", "line\nbreak", "\U0001f600", "", "deadbeef", "0.0.0.0", "日本語"]
INCLUDE_FLOATS = "--floats" in sys.argv


def rnd_json(depth=0):
    choices = ["str", "int", "bool", "null", "list", "obj"]
    if INCLUDE_FLOATS:
        choices.append("float")
    if depth >= 3:
        choices = ["str", "int", "bool", "null"]
    t = random.choice(choices)
    if t == "str":
        return random.choice(STRS)
    if t == "int":
        return random.randint(-10**12, 10**18)
    if t == "float":
        return random.choice([0.0, 1.5, -2.25, 3.14159, 1e20, 1e-7, 100.0, 0.1])
    if t == "bool":
        return random.choice([True, False])
    if t == "null":
        return None
    if t == "list":
        return [rnd_json(depth + 1) for _ in range(random.randint(0, 4))]
    return {random.choice(KEYS): rnd_json(depth + 1) for _ in range(random.randint(0, 4))}


def rnd_payload():
    return {random.choice(KEYS): rnd_json(1) for _ in range(random.randint(0, 5))}


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 1500
    random.seed(98765)

    py_db = tempfile.mktemp(suffix=".db")
    rs_db = tempfile.mktemp(suffix=".db")
    pst = EventBusStorage(py_db)
    rbus = pi_core.EventBus(rs_db)

    mism = []
    used_corr = set()
    for i in range(n):
        et = random.choice(EVENT_TYPES)
        pk = random.choice(PARTITIONS)
        tenant = random.choice(TENANTS)
        actor = "actor" + str(random.randint(1, 3))
        corr = random.choice(CORRS)
        used_corr.add(corr)
        payload = rnd_payload()
        marker = TimestampMarker(
            wall_time=datetime(2026, 1, 1, 0, 0, 0, (i % 999999) + 1, tzinfo=timezone.utc),
            sequence_number=(i % 1000), clock_id="eventbus",
        )
        ts = canonical_timestamp(marker.wall_time)
        ok = marker.ordering_key
        try:
            py = pst.append(EventType(et), pk, payload, tenant, actor, corr, clock=FakeClock(marker)).serialize()
        except Exception as ex:
            py = {"__err__": type(ex).__name__}
        try:
            rs = json.loads(rbus.append(et, pk, json.dumps(payload), tenant, actor, corr, ts, ok, FIXED_CREATED_ISO))
        except Exception as ex:
            rs = {"__err__": type(ex).__name__}
        if py != rs:
            mism.append(("append", i, payload, py, rs))
            if len(mism) > 20:
                break

    # full read comparison across partitions + correlations + stats + chains
    for pk in PARTITIONS:
        a = [e.serialize() for e in pst.read_partition(pk, 1, 10**6)]
        b = json.loads(rbus.read_partition(pk, 1, 10**6))
        if a != b:
            mism.append(("read_partition", pk, None, len(a), len(b)))
        pa, pe = pst.verify_partition_chain(pk)
        rc = json.loads(rbus.verify_partition_chain(pk))
        if {"ok": pa, "errors": pe} != rc:
            mism.append(("chain", pk, None, {"ok": pa, "errors": pe}, rc))
    for corr in sorted(used_corr):
        a = [e.serialize() for e in pst.read_by_correlation(corr)]
        b = json.loads(rbus.read_by_correlation(corr))
        if a != b:
            mism.append(("read_by_correlation", corr, None, len(a), len(b)))
    if pst.get_stats() != json.loads(rbus.get_stats()):
        mism.append(("stats", None, None, pst.get_stats(), json.loads(rbus.get_stats())))

    os.remove(py_db)
    os.remove(rs_db)

    mode = "WITH floats" if INCLUDE_FLOATS else "no floats"
    print(f"event-fabric fuzz: {n} random appends + full read/chain/stats sweep ({mode})")
    if mism:
        print(f"  MISMATCHES: {len(mism)}")
        for label, k, payload, a, b in mism[:6]:
            print(f"    [{label} @ {k}] payload={payload}\n       py={a}\n       rs={b}")
        sys.exit(1)
    print("  MISMATCHES: 0  -> byte-identical events, hashes, chains, reads across the whole sequence")


if __name__ == "__main__":
    main()
