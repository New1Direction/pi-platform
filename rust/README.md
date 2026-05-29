# PI Platform — Rust Core (proof of architecture)

This directory is a **verified proof** that the PI Platform's deterministic
compute core can be ported to Rust and exposed to Python through PyO3 — the
two-language architecture from `rust-migration-plan.html`. It is **not** the
full port; it is the de-risking milestone, with a real port-velocity datapoint
and a behavioral-equivalence harness that gates every agent.

```
Rust core (pi-agents)  ──maturin/PyO3──▶  Python module `pi_core`  ◀── Python glue (FastAPI, LLM SDKs, Playwright)
```

## What's here

| Path | What it is |
|------|------------|
| `crates/pi-agents/` | Pure-Rust agent core. One module per agent under `src/agents/`, a name→fn `registry.rs`, and `pyutil.rs` (Python `splitlines`/`strip` semantics). |
| `crates/pi-py/` | The single PyO3 crate. Builds a `cdylib` named `pi_core` exposing `run_agent(name, input_json)` and `list_agents()`. |
| `parity/` | The equivalence harness: `test_parity.py` (curated samples), `fuzz_parity.py` (independent differential fuzzer), and one `specs/<agent>.py` per ported agent. |

## Status — 131 agents ported, fully verified

- **131** micro-agents ported to Rust (four parallel orchestration batches + 2 hand-built: the template and one whose subagent failed to write files).
- **484** Rust unit tests pass — deterministically, including under forced 16-thread parallelism.
- **1,335** curated parity tests pass — every ported agent is byte-identical to its Python original across hand-picked edge cases and env-var branches.
- **65,500** differential-fuzz comparisons per run — **0** divergences on inputs the porters never saw (CRLF / lone `\r` / `U+2028` / oversized / Unicode), including float-stress on the Shannon-entropy agent.

Equivalence — not "it compiles" — is the gate.

> **Learnings carried forward (each caught by the harness, not in production):**
>
> 1. **Env-var test isolation.** Agents reading `PI_*_STRICT_MODE` need their unit tests
>    serialized (`serial_test::#[serial]`) — `cargo test` runs parallel threads and a test
>    mutating a process-global env var leaks into siblings (flaky, never a real port bug).
>    10 agents needed this; it's now baked into the orchestration prompt so new env-reading
>    agents get `#[serial]` automatically.
>
> 4. **Config-file fallback.** `pi_llm_system_prompt_drift_sentry`'s strict-mode resolver
>    reads `~/.antigravitycli/config.json` then a `__file__`-relative repo config. The latter
>    path isn't reproducible from a compiled lib; in this repo the key is absent so it resolves
>    to the `True` default — the Rust port replicates env + home-config and documents the rest.
>
> 2. **Non-deterministic originals.** `pi_threat_model_generator` builds a list via
>    `list(set(...))` — order is hash-randomized per CPython process, so byte-identical
>    parity is *impossible* and the Rust port is arguably more correct (stable order). The
>    harness compares such fields order-insensitively via a spec-level `NORMALIZE = [...]`
>    declaration. Only 1 of 96 agents; the other three `set()` users use it for membership
>    only (order-safe). **The "deterministic platform" contains non-deterministic agents.**
>
> 3. **`\s` is fine.** The Rust `regex` crate's `\s` IS Unicode-aware by default (matches
>    Python `re` on NBSP / U+2028 / thin-space / ideographic-space) — verified by direct
>    probe. Porters' repeated caveat that it's "ASCII-only" was over-cautious; no action needed.

## Build & test

```bash
# 1. Rust core (pure, no Python needed)
cd rust && cargo test -p pi-agents          # 91 unit tests

# 2. Build the PyO3 extension into the PoC venv
cd /path/to/pi-platform
uv venv .venv-poc --python 3.11
uv pip install --python .venv-poc pydantic pytest maturin
source .venv-poc/bin/activate
cd rust/crates/pi-py && maturin develop      # installs `pi_core`

# 3. Parity (Rust output == original Python output)
cd ../../parity
python -m pytest -q                          # 223 curated samples
PYTHONPATH=.:../../src python fuzz_parity.py 1000   # 25k differential comparisons
```

## Porting a new agent

1. Mirror `crates/pi-agents/src/agents/jwt_none_sentry.rs`: serde `Input`/`Output`
   structs with **field names identical to the Pydantic models**, a pure scan
   `fn`, and `run_json`. Use `crate::pyutil::{splitlines, strip}` wherever the
   Python used `.splitlines()` / `.strip()`.
2. Add `pub mod <name>;` to `agents/mod.rs` and an `m.insert("<PyClassName>", …)`
   to `registry.rs` (both are mechanically regenerable from the file set).
3. Write `parity/specs/<name>.py` (see any existing spec) with 6–10 diverse
   samples, then run the suite. A port isn't done until parity is green.

## Known parity caveats (carried forward to the full port)

The orchestration surfaced these real risks; all are currently handled or bounded:

- **Line/space semantics** — Rust `.lines()`/`.trim()` ≠ Python `.splitlines()`/`.strip()`. Always go through `pyutil`. (Covered.)
- **`regex` crate** has no lookahead/lookbehind/backreferences. Agents using them must be restructured; the porter must flag it. (None in this batch needed it.)
- **Float exactness** — agents emitting floats (entropy, scores) rely on IEEE-754 f64 matching CPython. Verified bit-identical here (incl. 5k entropy trials), but `round()` (banker's rounding) and division-heavy agents need per-agent checking.
- **Unicode case folding** — Python `str.lower()` vs Rust `to_lowercase()` can differ on exotic codepoints; immaterial for ASCII trigger tokens but noted.

## Agent-corpus triage (informs scope)

Of **299** agent files in `src/pi_micro_agents/` (excluding `__init__.py`):

| Category | Count |
|----------|-------|
| Functional (real class defs) — **portable** | **239** |
| Genuine `SyntaxError` (broken in the current product) | 51 |
| Escaped-string stubs (recoverable via `ast.literal_eval`) | 6 |
| Parse-OK but no class | 3 |

The honest portable surface is **239**, of which **198** are clean and
self-contained (stdlib + pydantic only). Porting to Rust *surfaces* the 51
broken files (they fail to compile rather than silently no-op at import).
