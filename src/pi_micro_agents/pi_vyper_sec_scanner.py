from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_VYPER_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_VYPER_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class VyperScannerInput(BaseModel):
    file_path: str = Field(..., description="Vyper source file path")
    vyper_code: str = Field(..., description="Vyper source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")


class VyperScannerOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Vyper code is free from compiler/decorator issues")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed line and violation findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(
        ..., description="Status classification (PASSED, WARN_VYPER_VULNERABILITY, REJECTED_VYPER_VULNERABILITY)"
    )


# 3. Core Micro-Agent Class
class PiVyperSecScanner:
    """Specialized Web3 micro-agent that audits Vyper source code for compiler reentrancy bugs and decorator best practices."""

    def __init__(self) -> None:
        self.agent_name = "PiVyperSecScanner"

    def audit_vyper(self, input_envelope: VyperScannerInput) -> VyperScannerOutput:
        """Autonomously audits Vyper contracts for reentrancy bugs and decorator syntax."""
        code = input_envelope.vyper_code
        vulnerable_funcs = []
        flagged_findings = []

        # Clean comments (Vyper comments start with #)
        re.sub(r"#.*", "", code)

        # Mode 1: Compiler Bug Audit
        # Check version string in Vyper (usually declared as # @version ^0.3.7 or similar in comments)
        version_match = re.search(r"#\s*@version\s*([^\n\r]+)", code)
        if version_match:
            version_str = version_match.group(1).strip()
            # Flag vulnerable compiler versions < 0.3.10 containing known reentrancy lock slot clashes
            # e.g., ^0.2.0, 0.3.7, etc.
            if re.search(r"\b0\.2\.[0-9]+\b", version_str) or re.search(r"\b0\.3\.[0-9]\b", version_str):
                # If it uses nonreentrant lock, flag it
                if "@nonreentrant" in code:
                    vulnerable_funcs.append("global_compiler")
                    flagged_findings.append(
                        f"Vulnerable Vyper compiler version '{version_str}' detected with active @nonreentrant decorators. "
                        f"Versions < 0.3.10 have reentrancy lock slot allocation vulnerabilities."
                    )

        # Mode 2: Vyper Decorator and Syntax Best Practices
        # In Vyper, all functions must have an accessibility decorator (@external or @internal)
        # Find functions: def [name](...):
        lines = code.splitlines()
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("def ") and stripped.endswith(":"):
                func_name = stripped[4 : stripped.find("(")].strip()

                # Look at prior lines for decorators
                has_decorator = False
                decorator_line = ""
                # Search up to 3 lines prior
                for lookback in range(1, 4):
                    prev_idx = idx - lookback
                    if prev_idx >= 0:
                        prev_line = lines[prev_idx].strip()
                        if prev_line.startswith("@"):
                            has_decorator = True
                            decorator_line = prev_line
                            break

                if not has_decorator:
                    vulnerable_funcs.append(func_name)
                    flagged_findings.append(
                        f"Function '{func_name}' on Line {idx + 1} lacks access control or state decorator (@external/@internal)."
                    )
                else:
                    # Check for invalid decorators
                    valid_decorators = ["@external", "@internal", "@view", "@pure", "@payable", "@nonreentrant"]
                    dec_name = decorator_line.split("(")[0].strip()
                    if dec_name not in valid_decorators:
                        vulnerable_funcs.append(func_name)
                        flagged_findings.append(
                            f"Function '{func_name}' on Line {idx + 1} uses invalid/unrecognized decorator '{dec_name}'."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_VYPER_VULNERABILITY"
            else:
                status = "WARN_VYPER_VULNERABILITY"
                is_secure = True

        return VyperScannerOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
