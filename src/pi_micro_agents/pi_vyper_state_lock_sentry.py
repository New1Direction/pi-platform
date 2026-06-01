from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_VYPER_LOCK_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class VyperLockInput(BaseModel):
    file_path: str = Field(..., description="Vyper source file path")
    vyper_code: str = Field(..., description="Vyper source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class VyperLockOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Vyper reentrancy lock usage is secure")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed Vyper reentrancy lock safety findings"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_VYPER_LOCK_RISK, REJECTED_VYPER_LOCK_RISK)"
    )


# 3. Core Micro-Agent Class
class PiVyperStateLockSentry:
    """Specialized Web3 micro-agent that audits Vyper code for correct reentrancy mutex decorator configurations."""

    def __init__(self) -> None:
        self.agent_name = "PiVyperStateLockSentry"

    def audit_vyper_lock(self, input_envelope: VyperLockInput) -> VyperLockOutput:
        """Autonomously audits Vyper source code for `@nonreentrant` decorator safety violations."""
        code = input_envelope.vyper_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all function definitions in Vyper: @external or @internal followed by def funcName(...):
        func_blocks = re.findall(
            r"((?:@[a-zA-Z0-9_]+(?:\([^)]*\))?\s*)*)def\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^:]*:\s*([\s\S]*?)(?=\n\S|\Z)",
            code,
        )

        for decorators, name, _args, body in func_blocks:
            # Check if function performs external call: raw_call, ext_call, or self.
            has_external_call = (
                "raw_call" in body or "ext_call" in body or re.search(r"\b[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\(", body)
            )
            # Check if it has a nonreentrant decorator
            has_nonreentrant = "@nonreentrant" in decorators

            if has_external_call and not has_nonreentrant:
                # In Vyper, functions modifying state and performing external calls should use nonreentrant
                state_mod_patterns = [r"self\.[a-zA-Z0-9_]+\s*=", r"self\.[a-zA-Z0-9_]+\s*(\+=|-=)"]
                if any(re.search(pat, body) for pat in state_mod_patterns):
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' makes external calls and modifies local state but lacks the `@nonreentrant` decorator. "
                        "This may violate Vyper reentrancy safety guidelines."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_VYPER_LOCK_RISK"
            else:
                status = "WARN_VYPER_LOCK_RISK"
                is_secure = True

        return VyperLockOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
