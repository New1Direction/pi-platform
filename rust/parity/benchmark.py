"""Honest Rust-vs-Python benchmark (RELEASE build required).

Reuses the proven parity specs. For each agent, measures "input dict -> output
dict":
  - Python: spec.run_python(data)  (constructs the Pydantic Input + scans)
  - Rust:   json.loads(pi_core.run_agent(name, json.dumps(data)))  -- INCLUDES the
            full PyO3 + JSON boundary the app would actually pay.

IMPORTANT: build the extension with `maturin develop --release` first; a debug
build is 10-50x slower and would make this comparison meaningless.

Run:  PYTHONPATH=.:../../src python benchmark.py [iterations]
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

N = int(sys.argv[1]) if len(sys.argv) > 1 else 20000
SPECS = os.path.join(os.path.dirname(__file__), "specs")

# Realistic ~120-line source blob; replaces the (small) spec sample's str fields.
BLOB = "\n".join(
    [
        "import os, jwt, hashlib",
        "token = jwt.decode(req.token, key, algorithms=['HS256'])",
        "password = 'hunter2'  # secret",
        "api_key = os.getenv('API_KEY')",
        "tx.origin == msg.sender",
    ]
    + [f"x{i} = compute(value_{i}, factor={i})  # line {i} AKIAIOSFODNN7EXAMPLE" for i in range(115)]
)

AGENTS = [
    "jwt_none_sentry", "hardcoded_secret_detector", "git_secret_entropy_leak_sentry",
    "llm_prompt_injection_sentry", "sensitive_data_scanner", "solidity_flash_loan_attack",
]


def load_spec(stem):
    fp = os.path.join(SPECS, stem + ".py")
    s = importlib.util.spec_from_file_location("bench_" + stem, fp)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def big_input(template):
    return {k: (BLOB if isinstance(v, str) and k not in ("check_level", "file_path") else v)
            for k, v in template.items()}


def bench(fn):
    for _ in range(min(2000, N // 5)):
        fn()
    best = float("inf")
    batch = max(1, N // 5)
    for _ in range(5):
        t0 = time.perf_counter()
        for _ in range(batch):
            fn()
        best = min(best, (time.perf_counter() - t0) / batch)
    return best


def main():
    print(f"~{N} iters/op, realistic ~120-line input  (RELEASE build assumed)\n")
    print(f"{'agent':42} {'python':>11} {'rust+bndry':>12} {'speedup':>9}")
    print("-" * 78)
    speedups = []
    for stem in AGENTS:
        m = load_spec(stem)
        data = big_input(dict(m.SAMPLES[0]["input"]))
        name = m.RUST_NAME

        def py():
            return m.run_python(dict(data))

        def rs():
            return json.loads(pi_core.run_agent(name, json.dumps(data)))

        # parity sanity at the benchmarked input
        assert py() == json.loads(pi_core.run_agent(name, json.dumps(data))), f"parity break {stem}"
        pt, rt = bench(py), bench(rs)
        sp = pt / rt
        speedups.append(sp)
        print(f"{name[:42]:42} {pt*1e6:>8.2f}us {rt*1e6:>9.2f}us {sp:>8.2f}x")

    m0 = load_spec(AGENTS[0])
    empty = {k: ("" if isinstance(v, str) else v) for k, v in m0.SAMPLES[0]["input"].items()}
    empty_json = json.dumps(empty)
    name0 = m0.RUST_NAME

    def boundary():
        return pi_core.run_agent(name0, empty_json)
    bt = bench(boundary)
    print("-" * 78)
    print(f"PyO3+JSON boundary (empty input): {bt*1e6:.2f}us/call")
    sp_sorted = sorted(speedups)
    print(f"\nmedian integrated speedup: {sp_sorted[len(sp_sorted)//2]:.2f}x  "
          f"(range {min(speedups):.2f}x-{max(speedups):.2f}x)")


if __name__ == "__main__":
    main()
