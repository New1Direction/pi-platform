"""Parity spec for PiRustSolanaReentrancySentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRustSolanaReentrancySentry"

_mod = load_py_agent("pi_rust_solana_reentrancy_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRustSolanaReentrancySentry()
    out = agent.audit_solana_accounts(_mod.RustSolanaReentrancyInput(**data))
    return out.model_dump()


# Clean: a single mutable account -> no duplicate-mutability risk.
_SECURE = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Transfer<'info> {",
        "    #[account(mut)]",
        "    pub from: Account<'info, Token>,",
        "    pub authority: Signer<'info>,",
        "}",
    ]
)

# Two mutable accounts, NO uniqueness constraint -> flagged.
_DUAL_MUT_VULN = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Swap<'info> {",
        "    #[account(mut)]",
        "    pub account_a: Account<'info, Token>,",
        "    #[account(mut)]",
        "    pub account_b: Account<'info, Token>,",
        "}",
    ]
)

# Two mutable accounts WITH a `constraint = ... != ...` uniqueness check -> safe.
_DUAL_MUT_CONSTRAINT = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Swap<'info> {",
        "    #[account(mut, constraint = account_a.key() != account_b.key())]",
        "    pub account_a: Account<'info, Token>,",
        "    #[account(mut)]",
        "    pub account_b: Account<'info, Token>,",
        "}",
    ]
)

# Two mutable accounts; uniqueness enforced via `assert_ne!` anywhere in code.
_DUAL_MUT_ASSERT_NE = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Swap<'info> {",
        "    #[account(mut)]",
        "    pub account_a: Account<'info, Token>,",
        "    #[account(mut)]",
        "    pub account_b: Account<'info, Token>,",
        "}",
        "",
        "pub fn swap(ctx: Context<Swap>) -> Result<()> {",
        "    assert_ne!(ctx.accounts.account_a.key(), ctx.accounts.account_b.key());",
        "    Ok(())",
        "}",
    ]
)

# Three mutable accounts, none constrained -> flagged, all three listed.
_TRIPLE_MUT_VULN = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Rebalance<'info> {",
        "    #[account(mut)]",
        "    pub pool: Account<'info, Pool>,",
        "    #[account(mut)]",
        "    pub vault_a: Account<'info, Vault>,",
        "    #[account(mut)]",
        "    pub vault_b: Account<'info, Vault>,",
        "}",
    ]
)

# Two derive(Accounts) structs: one safe (constrained), one vulnerable.
_MULTI_STRUCT = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct SafeOp<'info> {",
        "    #[account(mut, constraint = src.key() != dst.key())]",
        "    pub src: Account<'info, Token>,",
        "    #[account(mut)]",
        "    pub dst: Account<'info, Token>,",
        "}",
        "",
        "#[derive(Accounts)]",
        "pub struct BadOp<'info> {",
        "    #[account(mut)]",
        "    pub x: Account<'info, Token>,",
        "    #[account(mut)]",
        "    pub y: Account<'info, Token>,",
        "}",
    ]
)

SAMPLES = [
    # Clean single-mutable struct -> PASSED.
    {"input": {"file_path": "lib.rs", "rust_code": _SECURE}},
    # Dual mutable, no constraint -> REJECTED.
    {"input": {"file_path": "lib.rs", "rust_code": _DUAL_MUT_VULN}},
    # Dual mutable with `constraint = ... != ...` -> PASSED.
    {"input": {"file_path": "lib.rs", "rust_code": _DUAL_MUT_CONSTRAINT}},
    # Dual mutable with `assert_ne!` elsewhere -> PASSED.
    {"input": {"file_path": "lib.rs", "rust_code": _DUAL_MUT_ASSERT_NE}},
    # Triple mutable, none constrained -> REJECTED, all listed.
    {"input": {"file_path": "lib.rs", "rust_code": _TRIPLE_MUT_VULN}},
    # Two structs, mixed safe/vulnerable.
    {"input": {"file_path": "lib.rs", "rust_code": _MULTI_STRUCT}},
    # Empty input -> no structs, PASSED.
    {"input": {"file_path": "lib.rs", "rust_code": ""}},
    # check_level override (does not affect logic) on a vulnerable input.
    {"input": {"file_path": "lib.rs", "rust_code": _DUAL_MUT_VULN, "check_level": "LENIENT"}},
    # Non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"file_path": "lib.rs", "rust_code": _DUAL_MUT_VULN},
     "env": {"PI_RUST_SOLANA_REENTRANCY_STRICT_MODE": "false"}},
    # Strict env -> REJECTED path.
    {"input": {"file_path": "lib.rs", "rust_code": _DUAL_MUT_VULN},
     "env": {"PI_RUST_SOLANA_REENTRANCY_STRICT_MODE": "true"}},
]
