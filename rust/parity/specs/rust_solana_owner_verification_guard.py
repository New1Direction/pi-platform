"""Parity spec for PiRustSolanaOwnerVerificationGuard.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRustSolanaOwnerVerificationGuard"

_mod = load_py_agent("pi_rust_solana_owner_verification_guard.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRustSolanaOwnerVerificationGuard()
    out = agent.audit_owner_verification(_mod.SolanaOwnerVerificationInput(**data))
    return out.model_dump()


# Clean: handler verifies owner against program_id -> PASSED.
_SECURE = (
    "fn process(ctx: AccountInfo) {\n"
    "    require(ctx.owner == program_id);\n"
    "}\n"
)

# Vulnerable: AccountInfo in args, body has no owner/program_id/Owner.
_VULN_ARGS = (
    "fn process(ctx: AccountInfo) {\n"
    "    let x = ctx.lamports;\n"
    "}\n"
)

# Vulnerable: AccountInfo only in body, no owner verification.
_VULN_BODY = (
    "fn handle(x: u64) {\n"
    "    let acc: AccountInfo = next();\n"
    "    let y = x + 1;\n"
    "}\n"
)

# Mixed: one safe (uses program_id), one vulnerable.
_MIXED = (
    "fn safe(a: AccountInfo) {\n"
    "    assert_eq!(a.owner, program_id);\n"
    "}\n"
    "fn unsafe_handler(b: AccountInfo) {\n"
    "    let z = b.data;\n"
    "}\n"
)

# Body contains the substring "Owner" (capitalized) -> treated as secure.
_OWNER_CAP = (
    "fn check(a: AccountInfo) {\n"
    "    verify_Owner(a);\n"
    "}\n"
)

# No AccountInfo anywhere -> never flagged, secure.
_NO_ACCOUNTINFO = (
    "fn add(a: u64, b: u64) {\n"
    "    let c = a + b;\n"
    "}\n"
)

SAMPLES = [
    {"input": {"file_path": "lib.rs", "rust_code": _SECURE}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_ARGS}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_BODY}},
    {"input": {"file_path": "lib.rs", "rust_code": _MIXED}},
    {"input": {"file_path": "lib.rs", "rust_code": _OWNER_CAP}},
    {"input": {"file_path": "lib.rs", "rust_code": _NO_ACCOUNTINFO}},
    {"input": {"file_path": "lib.rs", "rust_code": ""}},
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_ARGS, "check_level": "MEDIUM"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_ARGS},
     "env": {"PI_SOLANA_OWNER_VERIFICATION_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path
    {"input": {"file_path": "lib.rs", "rust_code": _VULN_ARGS},
     "env": {"PI_SOLANA_OWNER_VERIFICATION_STRICT_MODE": "true"}},
]
