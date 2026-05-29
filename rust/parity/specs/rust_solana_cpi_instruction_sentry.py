"""Parity spec for PiRustSolanaCPIInstructionSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRustSolanaCPIInstructionSentry"

_mod = load_py_agent("pi_rust_solana_cpi_instruction_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRustSolanaCPIInstructionSentry()
    out = agent.audit_cpi_instruction(_mod.SolanaCPIInstructionInput(**data))
    return out.model_dump()


# No CPI at all -> secure / PASSED.
_CLEAN = "fn process(ctx: Context) { msg!(\"hello\"); }"

# invoke() with no key/id/check token in the body -> flagged.
_VULN_INVOKE = "fn transfer(ctx: Context) { invoke(&ix, accounts); }"

# invoke_signed() with no key/id/check token -> flagged (substring 'invoke').
_VULN_SIGNED = "fn mint(ctx: Context) { invoke_signed(&ix, accounts, seeds); }"

# invoke() but body mentions '.key' -> guard satisfied, secure.
_SAFE_KEY = "fn transfer(ctx: Context) { assert_eq!(prog.key, expected); invoke(&ix, accs); }"

# invoke() but body mentions 'program_id' (contains 'id') -> secure.
_SAFE_ID = "fn transfer(ctx: Context) { require(prog == program_id); invoke(&ix, accs); }"

# invoke() but body mentions 'check' -> secure.
_SAFE_CHECK = "fn transfer(ctx: Context) { check_program(prog); invoke(&ix, accs); }"

# Multiple methods across newlines: one safe, one vulnerable.
_MULTI = "\n".join(
    [
        "fn safe_one(ctx: Context) {",
        "    assert_eq!(prog.key, expected);",
        "    invoke(&ix, accs);",
        "}",
        "",
        "fn bad_one(ctx: Context) {",
        "    invoke(&ix, accs);",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "lib.rs", "rust_code": _CLEAN}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_INVOKE}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_SIGNED}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_KEY}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_ID}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_CHECK}},
    {"input": {"file_path": "lib.rs", "rust_code": _MULTI}},
    {"input": {"file_path": "lib.rs", "rust_code": ""}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_INVOKE, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_INVOKE},
     "env": {"PI_SOLANA_CPI_INSTRUCTION_STRICT_MODE": "false"}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_INVOKE},
     "env": {"PI_SOLANA_CPI_INSTRUCTION_STRICT_MODE": "true"}},
]
