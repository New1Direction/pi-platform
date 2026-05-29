"""Concurrency benchmark: the consensus fabric's real shape.

The fabric runs CPU-bound agent scans under a ThreadPoolExecutor. Python's GIL
serializes CPU-bound work, so more threads ≈ no speedup. The Rust agents release
the GIL (Python::allow_threads), so they parallelize across cores. This measures
total wall time to process a fixed workload (R repeats × all agents) at varying
worker counts — the decisive test of whether the migration moves a real metric.

Run:  PYTHONPATH=.:../../src python concurrency_benchmark.py [repeats]  (RELEASE)
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
sys.path.insert(0, ".")
import pi_core  # noqa: E402

R = int(sys.argv[1]) if len(sys.argv) > 1 else 12
SPECS = os.path.join(os.path.dirname(__file__), "specs")
BLOB = "\n".join(
    ["import os, jwt", "token = jwt.decode(t, k, algorithms=['HS256'])", "password = 'hunter2'"]
    + [f"line_{i} = compute(v_{i})  # AKIAIOSFODNN7EXAMPLE selfdestruct {i}" for i in range(115)]
)


def load_specs():
    out = []
    for fn in sorted(os.listdir(SPECS)):
        if fn.endswith(".py") and not fn.startswith("_"):
            s = importlib.util.spec_from_file_location("c_" + fn[:-3], os.path.join(SPECS, fn))
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
            j = json.dumps(data)
            if m.run_python(dict(data)) == json.loads(pi_core.run_agent(m.RUST_NAME, j)):
                work.append((m, data, m.RUST_NAME, j))
        except Exception:
            pass

    cores = os.cpu_count() or 4
    py_tasks = [(m, d) for (m, d, _, _) in work] * R
    rs_tasks = [(n, j) for (_, _, n, j) in work] * R
    n_tasks = len(py_tasks)
    print(f"workload: {len(work)} agents x {R} = {n_tasks} scans; machine has {cores} cores\n")

    def py_one(t):
        m, d = t
        return m.run_python(dict(d))

    def rs_one(t):
        n, j = t
        return pi_core.run_agent(n, j)

    def pool_time(func, tasks, workers):
        # warmup
        with ThreadPoolExecutor(max_workers=workers) as ex:
            list(ex.map(func, tasks[: min(len(tasks), 200)]))
        best = float("inf")
        for _ in range(3):
            t0 = time.perf_counter()
            with ThreadPoolExecutor(max_workers=workers) as ex:
                list(ex.map(func, tasks))
            best = min(best, time.perf_counter() - t0)
        return best

    workers_list = sorted({1, 2, 4, min(8, cores), cores})
    print(f"{'workers':>8} {'Python(GIL)':>13} {'Rust(no-GIL)':>14} {'speedup':>9}")
    print("-" * 50)
    for w in workers_list:
        pt = pool_time(py_one, py_tasks, w)
        rt = pool_time(rs_one, rs_tasks, w)
        print(f"{w:>8} {pt*1e3:>10.1f}ms {rt*1e3:>11.1f}ms {pt/rt:>8.2f}x")
    print("-" * 50)
    print("If Python stays flat as workers rise (GIL) while Rust drops, that's the\n"
          "real migration win: true multi-core parallelism on the CPU-bound fabric.")


if __name__ == "__main__":
    main()
