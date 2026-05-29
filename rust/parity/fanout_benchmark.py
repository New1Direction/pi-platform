"""Realistic at-scale benchmark: full agent fan-out over one artifact.

The consensus fabric dispatches an artifact to MANY agents, each with a focused
envelope (the artifact in the field it scans, ~few KB) — NOT a 600KB union of
every agent's fields (see batch_benchmark.py for why that synthetic input is
misleading). This measures the realistic case: every parity-matched agent run
once on its own focused input.

Finding: the PyO3+JSON boundary is cheap (~0.3us/call), so per-call dispatch is
fine and batching to "amortize the boundary" buys ~nothing. The real win is
per-agent compute; aggregated over all agents it's ~2x (Python's validator is
pydantic-core, itself Rust, so it's a strong baseline). Individual compute-heavy
agents reach 4-12x (see benchmark.py).

Run:  PYTHONPATH=.:../../src python fanout_benchmark.py [reps]   (RELEASE build)
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

REPS = int(sys.argv[1]) if len(sys.argv) > 1 else 200
SPECS = os.path.join(os.path.dirname(__file__), "specs")
BLOB = "\n".join(
    ["import os, jwt", "token = jwt.decode(t, k, algorithms=['HS256'])", "password = 'hunter2'"]
    + [f"line_{i} = compute(v_{i})  # AKIAIOSFODNN7EXAMPLE selfdestruct {i}" for i in range(115)]
)


def load_specs():
    out = []
    for fn in sorted(os.listdir(SPECS)):
        if fn.endswith(".py") and not fn.startswith("_"):
            s = importlib.util.spec_from_file_location("f_" + fn[:-3], os.path.join(SPECS, fn))
            m = importlib.util.module_from_spec(s)
            try:
                s.loader.exec_module(m)
                out.append(m)
            except Exception:
                pass
    return out


def main():
    work = []
    for m in load_specs():
        data = {k: (BLOB if isinstance(v, str) and k != "check_level" else v)
                for k, v in m.SAMPLES[0]["input"].items()}
        try:
            if m.run_python(dict(data)) == json.loads(pi_core.run_agent(m.RUST_NAME, json.dumps(data))):
                work.append((m, data, json.dumps(data)))
        except Exception:
            pass
    K = len(work)
    avg = sum(len(j) for _, _, j in work) // max(1, K)
    print(f"full fan-out: K={K} parity-matched agents, avg focused input {avg} bytes, {REPS} reps\n")

    def bench(fn):
        for _ in range(max(5, REPS // 10)):
            fn()
        best = float("inf")
        for _ in range(5):
            t0 = time.perf_counter()
            for _ in range(REPS):
                fn()
            best = min(best, (time.perf_counter() - t0) / REPS)
        return best

    pt = bench(lambda: [m.run_python(dict(d)) for m, d, _ in work])
    rt = bench(lambda: [pi_core.run_agent(m.RUST_NAME, j) for m, _, j in work])

    print(f"{'path':14}{'per-fanout':>12}{'per-agent':>12}{'speedup':>10}")
    print("-" * 48)
    print(f"{'Python':14}{pt*1e3:>9.2f}ms{pt/K*1e6:>9.2f}us{'1.00x':>10}")
    print(f"{'Rust':14}{rt*1e3:>9.2f}ms{rt/K*1e6:>9.2f}us{pt/rt:>9.2f}x")
    print(f"\nfull fan-out of {K} agents/artifact: Python {pt*1e3:.1f}ms -> Rust {rt*1e3:.1f}ms ({pt/rt:.2f}x)")


if __name__ == "__main__":
    main()
