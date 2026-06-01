from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_SOLANA_SIGNER_ASSERTION_STRICT_MODE")


class SolanaSignerAssertionInput(BaseModel):
    file_path: str = Field(..., description="Rust source file path")
    rust_code: str = Field(..., description="Rust source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class SolanaSignerAssertionOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Solana signer assertions passed")
    vulnerable_instructions: List[str] = Field(
        default_factory=list, description="Vulnerable instruction or method names"
    )
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiRustSolanaSignerAssertionSentry:
    """Specialized Web3 micro-agent that audits Solana Rust programs to ensure account signer checks are correctly performed."""

    def __init__(self) -> None:
        self.agent_name = "PiRustSolanaSignerAssertionSentry"

    def audit_signer_assertion(self, input_envelope: SolanaSignerAssertionInput) -> SolanaSignerAssertionOutput:
        code = input_envelope.rust_code
        vulnerable_instructions = []
        flagged_findings = []

        # Find Solana instruction functions inside pub fn under impl blocks
        instructions = re.findall(
            r"pub\s+fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*(?:pub\s+fn|fn)|\Z)", code
        )

        for name, args, body in instructions:
            # Look for context loading, e.g. ctx: Context<Stake> or ctx: Context<Claims>
            ctx_match = re.search(r"ctx\s*:\s*Context\s*<\s*([a-zA-Z0-9_]+)\s*>", args)
            if ctx_match:
                struct_name = ctx_match.group(1)

                # Search the rust file for the corresponding account struct definition, e.g. #[derive(Accounts)] pub struct Stake<'info>
                struct_pattern = (
                    r"#\[derive\([^)]*Accounts[^)]*\)\][\s\S]*?struct\s+"
                    + re.escape(struct_name)
                    + r"[\s\S]*?\{([\s\S]*?)\}"
                )
                struct_match = re.search(struct_pattern, code)

                if struct_match:
                    struct_body = struct_match.group(1)

                    # Look for fields that are of type AccountInfo<'info> or UncheckedAccount<'info>
                    # Check if they have the #[account(signer)] attribute or a signer check constraint
                    # Anchor fields:
                    fields = re.findall(
                        r"(pub\s+)?([a-zA-Z0-9_]+)\s*:\s*(AccountInfo|UncheckedAccount|Account)", struct_body
                    )
                    for _, field_name, field_type in fields:
                        # Find the attributes above this field
                        has_signer_attribute = False
                        attribute_match = re.search(
                            rf"#\[account\(([^)]*)\)\]\s*(pub\s+)?{field_name}\s*:", struct_body
                        )
                        if attribute_match:
                            attr_content = attribute_match.group(1)
                            if "signer" in attr_content:
                                has_signer_attribute = True

                        # If it is an AccountInfo or UncheckedAccount and does NOT have signer validation
                        # And we expect it to be a authority or signer based on name (e.g. authority, user, payer)
                        if field_type in ["AccountInfo", "UncheckedAccount"]:
                            if any(x in field_name.lower() for x in ["authority", "signer", "user", "owner"]):
                                # Check if body manually asserts is_signer (e.g. ctx.accounts.authority.is_signer)
                                manual_signer_check = f"{field_name}.is_signer" in body or f"{field_name}.key" in body

                                if not has_signer_attribute and not manual_signer_check:
                                    vulnerable_instructions.append(name)
                                    flagged_findings.append(
                                        f"Solana instruction '{name}' uses accounts struct '{struct_name}' where field "
                                        f"'{field_name}' of type '{field_type}' has authority-like name but lacks Anchor "
                                        f"'#[account(signer)]' attribute and no explicit '.is_signer' verification was found "
                                        f"in the instruction body. This is vulnerable to signature verification bypass exploits."
                                    )

        is_secure = len(vulnerable_instructions) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SOLANA_SIGNER_ASSERTION"
            else:
                status = "WARN_SOLANA_SIGNER_ASSERTION"
                is_secure = True

        return SolanaSignerAssertionOutput(
            is_secure=is_secure,
            vulnerable_instructions=vulnerable_instructions,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
