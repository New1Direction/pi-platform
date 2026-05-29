"""Parity spec for PiRustAnchorSecuritySentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRustAnchorSecuritySentry"

_mod = load_py_agent("pi_rust_anchor_security_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRustAnchorSecuritySentry()
    out = agent.audit_anchor_security(_mod.AnchorSecurityInput(**data))
    return out.model_dump()


# A clean instruction whose Accounts struct validates the signer.
_SECURE = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Initialize<'info> {",
        "    pub authority: Signer<'info>,",
        "    pub data: Account<'info, Data>,",
        "}",
        "pub fn initialize(ctx: Context<Initialize>) -> Result<()> { Ok(()) }",
    ]
)

# Missing Signer entirely -> flagged vulnerable.
_VULN = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Initialize<'info> {",
        "    pub authority: AccountInfo<'info>,",
        "    pub data: Account<'info, Data>,",
        "}",
        "pub fn initialize(ctx: Context<Initialize>) -> Result<()> { Ok(()) }",
    ]
)

# Struct has no 'Signer' type but a field literally named 'signer' -> the
# lowercase substring check makes this PASS (covers the .lower() branch).
_LOWER_SIGNER = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Withdraw<'info> {",
        "    pub signer: AccountInfo<'info>,",
        "    pub vault: Account<'info, Vault>,",
        "}",
        "pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> { Ok(()) }",
    ]
)

# A pub fn that does NOT take a Context arg -> never inspected.
_NO_CONTEXT = "\n".join(
    [
        "pub fn helper(a: u64, b: u64) -> u64 { a + b }",
    ]
)

# Context generic exists but no matching #[derive(Accounts)] struct block ->
# struct_match is None -> not flagged.
_NO_STRUCT = "\n".join(
    [
        "pub fn run(ctx: Context<Missing>) -> Result<()> { Ok(()) }",
    ]
)

# Two instructions: one safe, one vulnerable.
_MIXED = "\n".join(
    [
        "#[derive(Accounts)]",
        "pub struct Safe<'info> {",
        "    pub admin: Signer<'info>,",
        "}",
        "#[derive(Accounts)]",
        "pub struct Unsafe<'info> {",
        "    pub admin: AccountInfo<'info>,",
        "}",
        "pub fn do_safe(ctx: Context<Safe>) -> Result<()> { Ok(()) }",
        "pub fn do_unsafe(ctx: Context< Unsafe >) -> Result<()> { Ok(()) }",
    ]
)

SAMPLES = [
    {"input": {"file_path": "lib.rs", "rust_code": _SECURE}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN}},
    {"input": {"file_path": "lib.rs", "rust_code": _LOWER_SIGNER}},
    {"input": {"file_path": "lib.rs", "rust_code": _NO_CONTEXT}},
    {"input": {"file_path": "lib.rs", "rust_code": _NO_STRUCT}},
    {"input": {"file_path": "lib.rs", "rust_code": _MIXED}},
    {"input": {"file_path": "lib.rs", "rust_code": ""}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN, "check_level": "MEDIUM"}},
    # strict env -> REJECTED path
    {"input": {"file_path": "lib.rs", "rust_code": _VULN},
     "env": {"PI_ANCHOR_SECURITY_STRICT_MODE": "true"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "lib.rs", "rust_code": _VULN},
     "env": {"PI_ANCHOR_SECURITY_STRICT_MODE": "false"}},
]
