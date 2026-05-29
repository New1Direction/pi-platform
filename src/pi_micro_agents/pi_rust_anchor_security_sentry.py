from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ANCHOR_SECURITY_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_ANCHOR_SECURITY_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class AnchorSecurityInput(BaseModel):
    file_path: str = Field(..., description="Solana Anchor Rust source file path")
    rust_code: str = Field(..., description="Rust source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class AnchorSecurityOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Solana Anchor program conforms to security standards")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable instruction or struct names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed Anchor program safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_ANCHOR_RISK, REJECTED_ANCHOR_RISK)")


# 3. Core Micro-Agent Class
class PiRustAnchorSecuritySentry:
    """Specialized Solana micro-agent that audits Anchor Rust programs for signer and account validation defects."""

    def __init__(self) -> None:
        self.agent_name = "PiRustAnchorSecuritySentry"

    def audit_anchor_security(self, input_envelope: AnchorSecurityInput) -> AnchorSecurityOutput:
        """Autonomously audits Solana Anchor structures and instruction handlers."""
        code = input_envelope.rust_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find instruction functions inside pub mod or standard Rust functions
        funcs = re.findall(r"pub\s+fn\s+([a-zA-Z0-9_]+)\s*\((.*?)\)", code)

        for name, args in funcs:
            # Anchor instruction handlers receive Context<T>
            if "Context" in args:
                # Get the context generic name, e.g. Context<Initialize>
                ctx_match = re.search(r"Context\s*<\s*([a-zA-Z0-9_]+)\s*>", args)
                if ctx_match:
                    struct_name = ctx_match.group(1)
                    # Find the corresponding account struct block in code: e.g. #[derive(Accounts)] pub struct Initialize<'info> { ... }
                    struct_pattern = r"#\[derive\s*\(\s*Accounts\s*\)\s*\]\s*pub\s+struct\s+" + struct_name + r"[^}]+}"
                    struct_match = re.search(struct_pattern, code)
                    if struct_match:
                        struct_body = struct_match.group(0)
                        # Check for signer check: should contain Signer<'info>
                        if "Signer" not in struct_body and "signer" not in struct_body.lower():
                            vulnerable_funcs.append(name)
                            flagged_findings.append(
                                f"Anchor context struct '{struct_name}' for instruction '{name}' does not validate "
                                "the caller signature (missing 'Signer' type). This allows arbitrary clients to execute administrative calls."
                            )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ANCHOR_RISK"
            else:
                status = "WARN_ANCHOR_RISK"
                is_secure = True

        return AnchorSecurityOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
