"""Parity spec for PiRustTokioDeadlockSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRustTokioDeadlockSentry"

_mod = load_py_agent("pi_rust_tokio_deadlock_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRustTokioDeadlockSentry()
    out = agent.audit_tokio_deadlock(_mod.RustTokioDeadlockInput(**data))
    return out.model_dump()


# Clean: tokio::sync Mutex (not std::sync/parking_lot) -> has_std_mutex False,
# regex block skipped entirely.
_CLEAN_TOKIO = "\n".join(
    [
        "use tokio::sync::Mutex;",
        "async fn f() {",
        "    let g = shared.lock().await;",
        "    do_work().await;",
        "}",
    ]
)

# std::sync Mutex + .await present, but .await precedes .lock() so the
# lock-across-await regex does NOT match, and no async...block_on. PASSES even
# though the regex block runs.
_PASS_REGEX_RUN = "\n".join(
    [
        "use std::sync::Mutex;",
        "async fn f() {",
        "    do_io().await;",
        "}",
        "fn sync_use() {",
        "    let g = SHARED.lock();",
        "}",
    ]
)

# sync_lock_held_across_await: std::sync Mutex, .lock() then .await.
_SYNC_LOCK_AWAIT = "\n".join(
    [
        "use std::sync::Mutex;",
        "async fn handler() {",
        "    let guard = SHARED.lock();",
        "    network_call().await;",
        "}",
    ]
)

# block_on_inside_async: parking_lot RwLock to satisfy has_std_mutex gate,
# async block with block_on(, and an .await for has_await.
_BLOCK_ON = "\n".join(
    [
        "use parking_lot::RwLock;",
        "async fn worker() {",
        "    something().await;",
        "    runtime.block_on(future);",
        "}",
    ]
)

# BOTH findings: std::sync Mutex, .lock() across .await AND async...block_on(.
_BOTH = "\n".join(
    [
        "use std::sync::Mutex;",
        "async fn h() {",
        "    let g = shared.lock();",
        "    do_work().await;",
        "    rt.block_on(other());",
        "}",
    ]
)

# Gating: std::sync Mutex + .lock() + block_on present, but NO .await anywhere
# -> has_await False -> regex block skipped -> PASSES.
_NO_AWAIT_GATE = "\n".join(
    [
        "use std::sync::Mutex;",
        "fn h() {",
        "    let g = m.lock();",
        "    rt.block_on(x);",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "a.rs", "rust_code": _CLEAN_TOKIO}},
    {"input": {"file_path": "b.rs", "rust_code": _PASS_REGEX_RUN}},
    {"input": {"file_path": "c.rs", "rust_code": _SYNC_LOCK_AWAIT}},
    {"input": {"file_path": "d.rs", "rust_code": _BLOCK_ON}},
    {"input": {"file_path": "e.rs", "rust_code": _BOTH}},
    {"input": {"file_path": "f.rs", "rust_code": _NO_AWAIT_GATE}},
    {"input": {"file_path": "g.rs", "rust_code": ""}},
    {"input": {"file_path": "h.rs", "rust_code": _SYNC_LOCK_AWAIT, "check_level": "LENIENT"}},
    # strict env -> REJECTED
    {"input": {"file_path": "i.rs", "rust_code": _BOTH},
     "env": {"PI_RUST_TOKIO_DEADLOCK_ST_STRICT_MODE": "true"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "j.rs", "rust_code": _BOTH},
     "env": {"PI_RUST_TOKIO_DEADLOCK_ST_STRICT_MODE": "false"}},
]
