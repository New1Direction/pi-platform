"""Parity spec for PiRustTuiResourceLimit.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRustTuiResourceLimit"

_mod = load_py_agent("pi_rust_tui_resource_limit.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRustTuiResourceLimit()
    out = agent.audit_tui_resources(_mod.RustTuiResourceLimitInput(**data))
    return out.model_dump()


# A clean rendering loop that throttles via event::poll + Duration::from.
_SECURE = "\n".join(
    [
        "loop {",
        "    terminal.draw(|f| ui(f))?;",
        "    if event::poll(Duration::from_millis(16))? {",
        "        handle_events()?;",
        "    }",
        "}",
    ]
)

# Drawing loop with NO throttling -> flagged (terminal.draw token).
_VULN_TERMINAL_DRAW = "\n".join(
    [
        "loop {",
        "    terminal.draw(|f| ui(f))?;",
        "}",
    ]
)

# Uses Terminal::draw form, no throttle -> flagged.
_VULN_TERMINAL_COLONS = "loop { Terminal::draw(&mut term, |f| render(f)); }"

# Uses bare draw( form, no throttle -> flagged.
_VULN_BARE_DRAW = "while running { draw(frame); }"

# Drawing present but throttled via sleep( -> secure.
_THROTTLE_SLEEP = "loop { terminal.draw(|f| ui(f))?; thread::sleep(d); }"

# Drawing present but throttled via tick( -> secure.
_THROTTLE_TICK = "loop { terminal.draw(|f| ui(f))?; ticker.tick(); }"

# No drawing calls at all -> secure regardless.
_NO_DRAW = "\n".join(
    [
        "fn main() {",
        "    println!(\"no tui here\");",
        "}",
    ]
)


SAMPLES = [
    # Clean / passing input.
    {"input": {"file_path": "main.rs", "rust_code": _SECURE}},
    # terminal.draw without throttle -> REJECTED (strict default).
    {"input": {"file_path": "main.rs", "rust_code": _VULN_TERMINAL_DRAW}},
    # Terminal::draw form, no throttle -> REJECTED.
    {"input": {"file_path": "main.rs", "rust_code": _VULN_TERMINAL_COLONS}},
    # bare draw( form, no throttle -> REJECTED.
    {"input": {"file_path": "main.rs", "rust_code": _VULN_BARE_DRAW}},
    # draw + sleep( throttle -> secure / PASSED.
    {"input": {"file_path": "main.rs", "rust_code": _THROTTLE_SLEEP}},
    # draw + tick( throttle -> secure / PASSED.
    {"input": {"file_path": "main.rs", "rust_code": _THROTTLE_TICK}},
    # No drawing calls -> secure / PASSED.
    {"input": {"file_path": "main.rs", "rust_code": _NO_DRAW}},
    # Empty / edge input -> no draw -> PASSED.
    {"input": {"file_path": "main.rs", "rust_code": ""}},
    # check_level override (still STRICT default behaviour via env).
    {"input": {"file_path": "main.rs", "rust_code": _VULN_TERMINAL_DRAW, "check_level": "LENIENT"}},
    # Non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "main.rs", "rust_code": _VULN_TERMINAL_DRAW},
     "env": {"PI_RUST_TUI_RESOURCE_LIMIT_STRICT_MODE": "false"}},
    # Strict env explicitly -> REJECTED.
    {"input": {"file_path": "main.rs", "rust_code": _VULN_TERMINAL_DRAW},
     "env": {"PI_RUST_TUI_RESOURCE_LIMIT_STRICT_MODE": "true"}},
]
