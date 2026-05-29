"""Parity spec for PiRustSolanaReentrancyCrossProgramSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRustSolanaReentrancyCrossProgramSentry"

_mod = load_py_agent("pi_rust_solana_reentrancy_cross_program_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRustSolanaReentrancyCrossProgramSentry()
    out = agent.audit_reentrancy_cross(_mod.SolanaReentrancyCrossInput(**data))
    return out.model_dump()


# Clean handler: no CPI at all -> secure.
_SECURE = "\n".join(
    [
        "pub fn safe_handler(ctx: Context) -> Result<()> {",
        "    let amount = ctx.accounts.state.value;",
        "    msg!(\"ok\");",
        "    Ok(())",
        "}",
    ]
)

# CPI followed by an assignment (`=`) -> vulnerable.
_CPI_ASSIGN = "\n".join(
    [
        "pub fn deposit(ctx: Context) -> Result<()> {",
        "    invoke(&ix, &accounts)?;",
        "    ctx.accounts.state.value = 42;",
        "    Ok(())",
        "}",
    ]
)

# invoke_signed followed by `mut ` -> vulnerable (exercises the optional group).
_CPI_MUT = "\n".join(
    [
        "pub fn withdraw(ctx: Context) -> Result<()> {",
        "    invoke_signed(&ix, &accounts, signers)?;",
        "    let mut remaining = 10;",
        "    Ok(())",
        "}",
    ]
)

# CPI followed by `serialize` -> vulnerable.
_CPI_SERIALIZE = "\n".join(
    [
        "pub fn settle(ctx: Context) -> Result<()> {",
        "    invoke(&ix)?;",
        "    state.serialize(&mut writer)?;",
        "    Ok(())",
        "}",
    ]
)

# CPI present but no post-mutation marker -> secure.
_CPI_CLEAN = "\n".join(
    [
        "pub fn forward(ctx: Context) -> Result<()> {",
        "    invoke(&ix, &accounts)?;",
        "    Ok(())",
        "}",
    ]
)

# Multiple handlers; only the second mutates state after CPI.
_MULTI = "\n".join(
    [
        "fn finalize_first(ctx: Context) -> Result<()> {",
        "    ctx.accounts.vault.amount = 0;",
        "    invoke(&ix)?;",
        "    Ok(())",
        "}",
        "fn finalize_second(ctx: Context) -> Result<()> {",
        "    invoke_signed(&ix, accs, seeds)?;",
        "    ctx.accounts.vault.amount = 5;",
        "    Ok(())",
        "}",
    ]
)

# Word "invoke" without a following paren -> re.split yields one part, so the
# post-CPI mutation check never runs even though `mut ` is present.
_INVOKE_WORD_ONLY = "\n".join(
    [
        "fn note(ctx: Context) -> Result<()> {",
        "    // we do not invoke anything here",
        "    let mut count = 0;",
        "}",
    ]
)


SAMPLES = [
    {"input": {"file_path": "lib.rs", "rust_code": _SECURE}},
    {"input": {"file_path": "lib.rs", "rust_code": _CPI_ASSIGN}},
    {"input": {"file_path": "lib.rs", "rust_code": _CPI_MUT}},
    {"input": {"file_path": "lib.rs", "rust_code": _CPI_SERIALIZE}},
    {"input": {"file_path": "lib.rs", "rust_code": _CPI_CLEAN}},
    {"input": {"file_path": "lib.rs", "rust_code": _MULTI}},
    {"input": {"file_path": "lib.rs", "rust_code": _INVOKE_WORD_ONLY}},
    {"input": {"file_path": "lib.rs", "rust_code": ""}},
    {"input": {"file_path": "lib.rs", "rust_code": _CPI_ASSIGN, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "lib.rs", "rust_code": _CPI_ASSIGN},
     "env": {"PI_SOLANA_REENTRANCY_CROSS_STRICT_MODE": "false"}},
    {"input": {"file_path": "lib.rs", "rust_code": _CPI_ASSIGN},
     "env": {"PI_SOLANA_REENTRANCY_CROSS_STRICT_MODE": "true"}},
]
