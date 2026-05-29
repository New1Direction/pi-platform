"""Integration test for the flag-gated Rust acceleration in the consensus fabric.

Verifies the two guarantees of the shim in `pi_micro_agents/orchestrator/consensus.py`:
  1. flag OFF (default)  -> _try_rust_agent returns None  -> pure Python path (no change).
  2. flag ON            -> the Rust core runs the agent and the shim reconstructs the
                           agent's real Pydantic Output model, byte-identical to Python.

Requires the full app deps (fastapi) to import consensus; SKIPs gracefully if absent.

Run:  PYTHONPATH=.:../../src python consensus_integration_test.py   (after maturin develop)
"""
from __future__ import annotations

import importlib.util
import os
import sys

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.dirname(__file__))

try:
    import pi_micro_agents.orchestrator.consensus as C
    import pi_core  # noqa: F401
    from pydantic import BaseModel
except ModuleNotFoundError as e:
    print(f"SKIP consensus integration test (missing dep: {e.name}) — needs full app env + maturin build")
    sys.exit(0)

# (parity-spec stem, consensus agent class name, scan method) — all in the elif dispatch + ported
CHECKS = [
    ("arbitrage_guard", "PiArbitrageGuard", "analyze_spread"),
    ("git_sec_scanner", "PiGitSecScanner", "scan_file"),
    ("oracle_sentry", "PiOracleSentry", "audit_prices"),
    ("self_destruct_hunter", "PiSelfDestructHunter", "audit_selfdestruct"),
    ("centralization_sentry", "PiCentralizationSentry", "audit_centralization"),
    ("token_tax_detector", "PiTokenTaxDetector", "audit_token_tax"),
]


def load_spec(stem):
    s = importlib.util.spec_from_file_location("ci_" + stem, os.path.join(os.path.dirname(__file__), "specs", stem + ".py"))
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def input_model(mod, data):
    for v in vars(mod).values():
        if isinstance(v, type) and issubclass(v, BaseModel) and v is not BaseModel:
            try:
                v(**data)
                return v
            except Exception:
                pass
    return None


def main():
    fails = []

    # flag ON: shim output == Python output, real Output model reconstructed
    os.environ["PI_USE_RUST_AGENTS"] = "1"
    C._rust_agent_names.cache_clear()
    C._rust_core.cache_clear()
    for stem, cls, method in CHECKS:
        m = load_spec(stem)
        data = m.SAMPLES[0]["input"]
        Inp = input_model(m._mod, data)
        inp = Inp(**data)
        agent = getattr(m._mod, cls)()
        py = getattr(agent, method)(inp).model_dump()
        shim = C._try_rust_agent(cls, type(agent), inp)
        if shim is None or shim.model_dump() != py:
            fails.append(f"{cls}: flag-on shim != python (shim={shim is not None})")

    # flag OFF: returns None (Python path)
    os.environ["PI_USE_RUST_AGENTS"] = "0"
    m = load_spec("arbitrage_guard")
    ag = getattr(m._mod, "PiArbitrageGuard")()
    if C._try_rust_agent("PiArbitrageGuard", type(ag), None) is not None:
        fails.append("flag-off did not return None")

    if fails:
        print("CONSENSUS INTEGRATION: FAIL")
        for f in fails:
            print("  -", f)
        sys.exit(1)
    print(f"CONSENSUS INTEGRATION: OK — {len(CHECKS)}/{len(CHECKS)} agents byte-identical via Rust "
          "when flagged on; clean Python fallback when off.")


if __name__ == "__main__":
    main()
