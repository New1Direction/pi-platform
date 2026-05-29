"""Parity spec for PiRustSolanaSignerAssertionSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRustSolanaSignerAssertionSentry"

_mod = load_py_agent("pi_rust_solana_signer_assertion_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRustSolanaSignerAssertionSentry()
    out = agent.audit_signer_assertion(_mod.SolanaSignerAssertionInput(**data))
    return out.model_dump()


# Vulnerable: AccountInfo authority field, no signer attr, no manual check.
_VULN = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Stake<'info> {",
        "    #[account(mut)]",
        "    pub authority: AccountInfo<'info>,",
        "}",
        "",
        "pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {",
        "    let x = 1;",
        "    Ok(())",
        "}",
    ]
)

# Safe via #[account(signer)] attribute.
_SAFE_ATTR = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Stake<'info> {",
        "    #[account(signer)]",
        "    pub authority: AccountInfo<'info>,",
        "}",
        "",
        "pub fn stake(ctx: Context<Stake>) -> Result<()> {",
        "    Ok(())",
        "}",
    ]
)

# Safe via explicit manual `.is_signer` check in the body.
_SAFE_MANUAL = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Stake<'info> {",
        "    #[account(mut)]",
        "    pub authority: AccountInfo<'info>,",
        "}",
        "",
        "pub fn stake(ctx: Context<Stake>) -> Result<()> {",
        "    require!(ctx.accounts.authority.is_signer, ProgramError::MissingRequiredSignature);",
        "    Ok(())",
        "}",
    ]
)

# Safe via explicit `.key` reference in the body.
_SAFE_KEY = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Stake<'info> {",
        "    #[account(mut)]",
        "    pub user: UncheckedAccount<'info>,",
        "}",
        "",
        "pub fn stake(ctx: Context<Stake>) -> Result<()> {",
        "    let k = ctx.accounts.user.key();",
        "    Ok(())",
        "}",
    ]
)

# Safe because the field is typed `Account` (not AccountInfo/UncheckedAccount).
_SAFE_TYPED = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Stake<'info> {",
        "    pub authority: Account<'info, Config>,",
        "}",
        "",
        "pub fn stake(ctx: Context<Stake>) -> Result<()> {",
        "    Ok(())",
        "}",
    ]
)

# Field has a non-authority-like name -> not flagged even as raw AccountInfo.
_SAFE_NAME = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Stake<'info> {",
        "    pub pool: AccountInfo<'info>,",
        "}",
        "",
        "pub fn stake(ctx: Context<Stake>) -> Result<()> {",
        "    Ok(())",
        "}",
    ]
)

# Multiple instructions, multiple vulnerable fields, two distinct structs.
_MULTI = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Stake<'info> {",
        "    #[account(mut)]",
        "    pub authority: AccountInfo<'info>,",
        "    pub user: UncheckedAccount<'info>,",
        "}",
        "",
        "#[derive(Accounts)]",
        "pub struct Claim<'info> {",
        "    #[account(signer)]",
        "    pub owner: AccountInfo<'info>,",
        "}",
        "",
        "pub fn stake(ctx: Context<Stake>) -> Result<()> {",
        "    Ok(())",
        "}",
        "",
        "pub fn claim(ctx: Context<Claim>) -> Result<()> {",
        "    Ok(())",
        "}",
    ]
)

# No instructions / no derive(Accounts) at all.
_PLAIN = "\n".join(
    [
        "pub fn helper(x: u64) -> u64 {",
        "    x + 1",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "lib.rs", "rust_code": _VULN}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_ATTR}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_MANUAL}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_KEY}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_TYPED}},
    {"input": {"file_path": "lib.rs", "rust_code": _SAFE_NAME}},
    {"input": {"file_path": "lib.rs", "rust_code": _MULTI}},
    {"input": {"file_path": "lib.rs", "rust_code": _PLAIN}},
    {"input": {"file_path": "lib.rs", "rust_code": ""}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "lib.rs", "rust_code": _VULN},
     "env": {"PI_SOLANA_SIGNER_ASSERTION_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "lib.rs", "rust_code": _VULN},
     "env": {"PI_SOLANA_SIGNER_ASSERTION_STRICT_MODE": "true"}},
]
