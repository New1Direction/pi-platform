from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_VYPER_EXTERNAL_CALL_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class VyperExternalCallInput(BaseModel):
    file_path: str = Field(..., description="Vyper source file path")
    vyper_code: str = Field(..., description="Vyper source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class VyperExternalCallOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Vyper external call checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(
        default_factory=list, description="Detailed Vyper Checks-Effects-Interactions findings"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_VYPER_CALL_RISK, REJECTED_VYPER_CALL_RISK)"
    )


# 3. Core Micro-Agent Class
class PiVyperExternalCallSentry:
    """Specialized Web3 micro-agent that audits Vyper code to ensure external calls occur after state changes (Checks-Effects-Interactions)."""

    def __init__(self) -> None:
        self.agent_name = "PiVyperExternalCallSentry"

    def audit_vyper_external_call(self, input_envelope: VyperExternalCallInput) -> VyperExternalCallOutput:
        """Autonomously audits Vyper source code for Checks-Effects-Interactions reentrancy violations."""
        code = input_envelope.vyper_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all function definitions in Vyper
        func_blocks = re.findall(
            r"((?:@[a-zA-Z0-9_]+(?:\([^)]*\))?\s*)*)def\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^:]*:\s*([\s\S]*?)(?=\n\S|\Z)",
            code,
        )

        for _decorators, name, _args, body in func_blocks:
            lines = body.splitlines()
            external_call_seen = False
            first_ext_call_line = -1

            for idx, line in enumerate(lines):
                line_stripped = line.strip()
                # Exclude comments
                if line_stripped.startswith("#"):
                    continue

                # Check if this line is an external call
                if "ext_call" in line_stripped or "raw_call" in line_stripped:
                    external_call_seen = True
                    if first_ext_call_line == -1:
                        first_ext_call_line = idx

                # Check if state change happens after external call is seen
                if external_call_seen:
                    state_mod_patterns = [r"self\.[a-zA-Z0-9_]+\s*=", r"self\.[a-zA-Z0-9_]+\s*(\+=|-=)"]
                    if any(re.search(pat, line_stripped) for pat in state_mod_patterns):
                        vulnerable_funcs.append(name)
                        flagged_findings.append(
                            f"Function '{name}' modifies local state in line {idx + 1} ('{line_stripped}') "
                            f"after an external call was executed in line {first_ext_call_line + 1}. "
                            "This violates the Checks-Effects-Interactions pattern and introduces a potential reentrancy vulnerability."
                        )
                        break

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_VYPER_CALL_RISK"
            else:
                status = "WARN_VYPER_CALL_RISK"
                is_secure = True

        return VyperExternalCallOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
