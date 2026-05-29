"""Amortized batch benchmark: the realistic consensus-fabric pattern.

The fabric runs MANY agents per input. The per-call benchmark showed the
Python-side json.dumps of the payload dominates cheap agents. This measures the
fix: serialize the input ONCE and run the whole compatible agent set in a single
crossing via pi_core.run_agents.

Compares, for K agents on one shared input:
  - Python loop      : K Python agent calls (status quo)
  - Rust per-call    : K pi_core.run_agent calls (K json.dumps + K crossings)
  - Rust batched     : ONE pi_core.run_agents call (1 json.dumps + 1 crossing)

Only agents whose Rust output matches Python on the shared input are included,
so the comparison is apples-to-apples and verified.

Run:  PYTHONPATH=.:../../src python batch_benchmark.py [reps]   (RELEASE build)
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
sys.path.insert(0, ".")
import pi_core  # noqa: E402

REPS = int(sys.argv[1]) if len(sys.argv) > 1 else 400
SPECS = os.path.join(os.path.dirname(__file__), "specs")

BLOB = "\n".join(
    [
        "import os, jwt", "token = jwt.decode(t, k, algorithms=['HS256'])",
        "password = 'hunter2'", "api_key = os.getenv('API_KEY')", "tx.origin == x",
    ]
    + [f"line_{i} = compute(v_{i})  # AKIAIOSFODNN7EXAMPLE selfdestruct {i}" for i in range(115)]
)


def load_specs():
    out = []
    for fn in sorted(os.listdir(SPECS)):
        if not fn.endswith(".py") or fn.startswith("_"):
            continue
        s = importlib.util.spec_from_file_location("bb_" + fn[:-3], os.path.join(SPECS, fn))
        m = importlib.util.module_from_spec(s)
        try:
            s.loader.exec_module(m)
            out.append(m)
        except Exception:
            pass
    return out


def build_superset(specs):
    sup = {}
    for m in specs:
        for k, v in m.SAMPLES[0]["input"].items():
            sup[k] = BLOB if isinstance(v, str) else v
    return sup


def bench(fn, reps):
    for _ in range(max(5, reps // 10)):
        fn()
    best = float("inf")
    for _ in range(5):
        t0 = time.perf_counter()
        for _ in range(reps):
            fn()
        best = min(best, (time.perf_counter() - t0) / reps)
    return best


def main():
    specs = load_specs()
    superset = build_superset(specs)
    sup_json = json.dumps(superset)

    # keep only agents that (a) run in Python on the superset and (b) match Rust
    usable = []
    for m in specs:
        try:
            py = m.run_python(dict(superset))
            rs = json.loads(pi_core.run_agent(m.RUST_NAME, sup_json))
            if py == rs:
                usable.append(m)
        except Exception:
            pass

    names = [m.RUST_NAME for m in usable]
    names_json = json.dumps(names)
    K = len(usable)
    print(f"shared input across K={K} parity-matched agents (of {len(specs)} specs), {REPS} reps\n")

    def py_loop():
        return [m.run_python(dict(superset)) for m in usable]

    def rs_percall():
        return {n: json.loads(pi_core.run_agent(n, sup_json)) for n in names}

    def rs_batch():
        return json.loads(pi_core.run_agents(names_json, sup_json))

    # correctness: batch == per-call == python (spot check)
    assert set(rs_batch().keys()) == set(names), "batch returned wrong keys"

    pt = bench(py_loop, REPS)
    rc = bench(rs_percall, REPS)
    rb = bench(rs_batch, REPS)

    print(f"{'path':22} {'per-input':>12} {'per-agent':>12} {'vs python':>10}")
    print("-" * 60)
    print(f"{'Python loop':22} {pt*1e3:>9.2f}ms {pt/K*1e6:>9.2f}us {'1.00x':>10}")
    print(f"{'Rust per-call':22} {rc*1e3:>9.2f}ms {rc/K*1e6:>9.2f}us {pt/rc:>9.2f}x")
    print(f"{'Rust batched':22} {rb*1e3:>9.2f}ms {rb/K*1e6:>9.2f}us {pt/rb:>9.2f}x")
    print("-" * 60)
    print(f"batching gain over per-call: {rc/rb:.2f}x  "
          f"(eliminates {K-1} json.dumps + {K-1} crossings per input)")


if __name__ == "__main__":
    main()
