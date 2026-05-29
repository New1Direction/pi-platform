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
| `crates/pi-event-fabric/` | **Stateful module:** Rust port of `pi_event_fabric.bus.core` — SQLite-backed (`rusqlite`, bundled), cryptographically-chained append-only event log. `canonical.rs` = byte-exact CPython `json.dumps(sort_keys, ensure_ascii, compact)` incl. float repr; `event.rs` = SHA-256 event hashing; `storage.rs` = append/read/chain-verify/checkpoints with an **injectable clock**. |
| `crates/pi-py/` | The single PyO3 crate. Builds a `cdylib` named `pi_core` exposing `run_agent`/`list_agents` and the `EventBus` class. |
| `parity/` | The equivalence harness: `test_parity.py` (curated samples), `fuzz_parity.py` (independent differential fuzzer), and one `specs/<agent>.py` per ported agent. |

## Stateful core — event fabric (the architecture's real test)

The agent sweep proved the *pattern-matcher* half. `pi-event-fabric` proves the
**stateful, persistent, cryptographic** half — a SQLite-backed append-only event
bus with SHA-256 event chaining, partition offsets, checkpoints, and replay.

- **Byte-identical parity** with the Python original across a curated op sequence
  (multi-partition, multi-tenant, unicode/control/nested payloads, big ints,
  correlation grouping, tenant-filtered reads, tail, metadata, stats, chain
  verification, hash-verified checkpoints) — **including every SHA-256
  `event_hash` and the full chain**.
- **Randomized differential fuzz** (`event_fabric_fuzz.py`): 2,000+ random
  append sequences + full read/chain/stats sweep, **0 divergences** — both
  without and **with floats** (after porting CPython float repr into canonical JSON).

**The headline finding: the "DeterministicEventBus" is not deterministic.**
Its `DeterministicClock.now()` reads wall-clock time, so identical inputs hash
differently across runs (proven empirically); its `sequence_counter` is frozen
and never increments. The Rust port makes the clock **injectable**, so the bus
is *genuinely* deterministic — and the parity harness feeds both sides the same
clock to prove byte-identical hashing. The port is arguably more correct than
the original. (Saved as a project memory.)

Two more event-fabric modules' **deterministic cores** are ported and parity-verified
(`schema_governance_parity.py`, byte-identical incl. SHA-256):
- `schema/evolution.py` — schema fingerprinting, compatibility diff/validation,
  migration-path BFS, data migration (`pi_core.schema_op`).
- `governance/compiler.py` — rule/compiled hashing, the operator evaluator, and the
  fail-closed priority decision engine (`pi_core.governance_op`).

Each surfaced a real parity subtlety: schema violations interpolate a `str`-Enum
member, which on Python 3.9 renders as `"SchemaChangeType.NAME"` (not the value).
The SQLite registries (CRUD with `datetime('now')` timestamps) are non-deterministic
persistence plumbing, scoped out. Remaining event-fabric files (`ordering/shard`,
`bus/semantic_fabric`, `replay/cross_version`) build on these and are follow-on.

Run: `PYTHONPATH=.:../../src python event_fabric_parity.py`,
`… event_fabric_fuzz.py 2000 --floats`, `… schema_governance_parity.py` (after `maturin develop`).

## Status — 205 agents ported, fully verified

- **205** micro-agents ported to Rust (six parallel orchestration batches + 2 hand-built). This exhausts the clean self-contained pool (stdlib + pydantic, no relative imports).
- **779** Rust unit tests pass — deterministically, including under forced 16-thread parallelism.
- **2,145** curated parity tests pass — every ported agent is byte-identical to its Python original across hand-picked edge cases and env-var branches.
- **82,000** general differential-fuzz comparisons per run — **0** divergences on inputs the porters never saw (CRLF / lone `\r` / `U+2028` / oversized / Unicode), including float-stress on the Shannon-entropy agent.
- **8,500** *structured-code* fuzz comparisons (`fuzz_structured.py`) targeting the 17 agents whose originals used regex lookaround — random Solidity/Vyper/Circom function blocks with nested braces, newline-spanning args, CRLF — **0** divergences.

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
> 5. **A real port bug — i64 overflow.** `memorystore_connection_auditor` parsed the Redis
>    port with `i64::parse`, which overflows on 20+ digit ports and spuriously set
>    `is_valid=false`. Python's `int()` is arbitrary precision (its `except ValueError` is
>    dead code), so it never invalidates. Fixed with `i128` + saturate; `is_valid`/`status`/
>    `issues` now match for all inputs. **Caught by a compiler dead-assignment warning**, then
>    a targeted huge-port test — the generic string fuzzer never synthesizes `rediss://h:<20 digits>/`.
>
> 6. **Non-portable fields → `sanitize()`.** Two agents emit values that can't be byte-matched
>    by nature: `niche_scraper` (`scraped_at = datetime.now()`, wall-clock) and
>    `gcp_iam_policy_risk_auditor` (embeds the JSON parser's error string; CPython `json` ≠
>    `serde_json` wording). Each spec defines `sanitize(out)` to drop/normalize just that field;
>    all deterministic fields are still compared. The agents' real behavior is identical.
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
- **`regex` crate** has no lookahead/lookbehind/backreferences. 17 agents needed it — their function-block regexes (`(?=\n\s*function|\Z)` etc.) were rewritten as header-match + manual body-span scanning. Verified byte-faithful by `fuzz_structured.py` (13.6k structured-code trials). One (`vyper_state_lock`) also had to extend Rust's whitespace set with `U+001C/1D/1E` to match Python's `\S`.
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
