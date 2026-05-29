"""Rust<->Python parity suite.

Discovers every spec in ``specs/`` and, for each declared sample, asserts the
Rust port (`pi_core.run_agent`) produces output identical to the original
Python agent. Equivalence is the gate — "it compiles" is not enough.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib

import pytest

import pi_core  # the Rust extension (maturin develop)

SPEC_DIR = pathlib.Path(__file__).parent / "specs"


def _load_specs():
    cases = []
    for fp in sorted(SPEC_DIR.glob("*.py")):
        if fp.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(f"parityspec_{fp.stem}", fp)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for i, sample in enumerate(mod.SAMPLES):
            cases.append((fp.stem, i, mod, sample))
    return cases


CASES = _load_specs()


def _normalize(out, mod):
    """Sort the order-unstable fields a spec declares in NORMALIZE."""
    fields = getattr(mod, "NORMALIZE", [])
    if not fields or not isinstance(out, dict):
        return out
    out = dict(out)
    for f in fields:
        if isinstance(out.get(f), list):
            out[f] = sorted(out[f], key=lambda x: json.dumps(x, sort_keys=True))
    return out


@pytest.mark.parametrize(
    "stem,idx,mod,sample",
    CASES,
    ids=[f"{stem}[{idx}]" for stem, idx, _, _ in CASES],
)
def test_parity(stem, idx, mod, sample):
    data = sample["input"]
    env = sample.get("env", {})

    # apply env overrides to BOTH implementations identically
    saved = {}
    for k, v in env.items():
        saved[k] = os.environ.get(k)
        os.environ[k] = v
    try:
        py_out = mod.run_python(dict(data))
        rs_raw = pi_core.run_agent(mod.RUST_NAME, json.dumps(data))
        rs_out = json.loads(rs_raw)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    # Some original agents derive a list via `list(set(...))`, whose order is
    # non-deterministic in CPython (per-process hash randomization). For such
    # fields a spec declares NORMALIZE = ["field", ...]; we compare them as
    # order-insensitive sets — testing the real contract, not a hash accident.
    py_out, rs_out = _normalize(py_out, mod), _normalize(rs_out, mod)

    # A spec may define sanitize(out) to drop/normalize fields that are
    # non-portable by nature (wall-clock timestamps; a foreign library's error
    # wording, e.g. CPython json vs serde_json). Applied identically to both.
    if hasattr(mod, "sanitize"):
        py_out, rs_out = mod.sanitize(py_out), mod.sanitize(rs_out)

    assert rs_out == py_out, (
        f"\nPARITY MISMATCH {stem}[{idx}] (agent={mod.RUST_NAME})"
        f"\n  input: {data}  env: {env}"
        f"\n  python: {py_out}"
        f"\n  rust:   {rs_out}"
    )


def test_registry_lists_specs():
    """Every spec's RUST_NAME must actually be registered in the Rust core."""
    registered = set(pi_core.list_agents())
    for fp in sorted(SPEC_DIR.glob("*.py")):
        if fp.name.startswith("_"):
            continue
        spec = importlib.util.spec_from_file_location(f"check_{fp.stem}", fp)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert mod.RUST_NAME in registered, f"{mod.RUST_NAME} not in Rust registry"
