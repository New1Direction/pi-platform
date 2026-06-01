from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_SOLANA_BORSH_LEAK_STRICT_MODE")


class SolanaBorshLeakInput(BaseModel):
    file_path: str = Field(..., description="Solana Rust source file path")
    rust_code: str = Field(..., description="Solana Rust source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class SolanaBorshLeakOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Borsh serialization is secure against memory leaks")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable structs or methods")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on Borsh memory leaks")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiRustSolanaBorshSerializationLeak:
    """Specialized Rust/Solana micro-agent that audits Borsh data structural alignment risking memory leakage."""

    def __init__(self) -> None:
        self.agent_name = "PiRustSolanaBorshSerializationLeak"

    def audit_borsh_leak(self, input_envelope: SolanaBorshLeakInput) -> SolanaBorshLeakOutput:
        code = input_envelope.rust_code
        vulnerable_elements = []
        flagged_findings = []

        # Find structs with BorshSerialize or AnchorSerialize
        struct_matches = re.finditer(
            r"#\[derive\([^)]*(BorshSerialize|AnchorSerialize)[^)]*\)\]\s*(?:pub\s+)?struct\s+([a-zA-Z0-9_]+)", code
        )

        for match in struct_matches:
            struct_name = match.group(2)
            # Find fields in this struct. Simple parser to look for dynamic/unbounded collections or raw padding
            struct_block = re.search(r"struct\s+" + struct_name + r"\s*\{([\s\S]*?)\}", code)
            if struct_block:
                fields = struct_block.group(1)
                # Check for dynamic structures or potential uninitialized data leaks (missing explicit padding or custom serialization bounds)
                if "Vec<" in fields or "String" in fields:
                    vulnerable_elements.append(struct_name)
                    flagged_findings.append(
                        f"Struct '{struct_name}' derives BorshSerialize/AnchorSerialize but contains dynamic length types (Vec or String) "
                        "without explicit field sizes or strict bounds checking. This risks serialization misalignment or data leakage during custom memory zeroing."
                    )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 65.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SOLANA_BORSH_LEAK"
            else:
                status = "WARN_SOLANA_BORSH_LEAK"
                is_secure = True

        return SolanaBorshLeakOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
