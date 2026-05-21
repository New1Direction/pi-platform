from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_RUST_SOLANA_REENTRANCY_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_RUST_SOLANA_REENTRANCY_STRICT_MODE", True))
        except Exception:
            pass
    return True


class RustSolanaReentrancyInput(BaseModel):
    file_path: str = Field(..., description="Rust source file path")
    rust_code: str = Field(..., description="Rust source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class RustSolanaReentrancyOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Solana Anchor reentrancy checks passed")
    vulnerable_instructions: List[str] = Field(default_factory=list, description="Vulnerable instruction struct names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiRustSolanaReentrancySentry:
    """Specialized Web3 micro-agent that audits Rust Solana Anchor programs to ensure no account uniqueness or duplicate mutability bugs exist."""

    def __init__(self) -> None:
        self.agent_name = "PiRustSolanaReentrancySentry"

    def audit_solana_accounts(self, input_envelope: RustSolanaReentrancyInput) -> RustSolanaReentrancyOutput:
        code = input_envelope.rust_code
        vulnerable_instructions = []
        flagged_findings = []

        # Find all structures annotated with #[derive(Accounts)]
        account_structs = re.findall(r'#\[derive\([^)]*Accounts[^)]*\)\][\s\S]*?pub struct\s+([a-zA-Z0-9_]+)\s*<[\s\S]*?\{([\s\S]*?)\}', code)

        for struct_name, struct_body in account_structs:
            # Look for mutable account fields
            mut_fields = re.findall(r'#\[account\([^)]*mut[^)]*\)\]\s*pub\s+([a-zA-Z0-9_]+)\s*:', struct_body)
            
            # If there are multiple mutable accounts declared, look for comparison constraints or assertions
            if len(mut_fields) > 1:
                # Check if there are constraints matching key uniqueness
                # E.g. constraint = account_a.key() != account_b.key()
                has_uniqueness_check = False
                for field in mut_fields:
                    # Is there a constraint containing "!=" and referencing other field keys in the struct body?
                    if re.search(rf'constraint\s*=.*{field}.*!=', struct_body) or "assert_ne!" in code:
                        has_uniqueness_check = True
                        break

                if not has_uniqueness_check:
                    vulnerable_instructions.append(struct_name)
                    flagged_findings.append(
                        f"Solana Accounts struct '{struct_name}' defines multiple mutable fields ({', '.join(mut_fields)}) "
                        f"but does not enforce account key uniqueness constraints. An attacker could pass duplicate "
                        f"mutable accounts to execute double-borrow or cross-account state corruptions."
                    )

        is_secure = len(vulnerable_instructions) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SOLANA_REENTRANCY"
            else:
                status = "WARN_SOLANA_REENTRANCY"
                is_secure = True

        return RustSolanaReentrancyOutput(
            is_secure=is_secure,
            vulnerable_instructions=vulnerable_instructions,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
