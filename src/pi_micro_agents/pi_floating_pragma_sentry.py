from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_PRAGMA_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_PRAGMA_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class PragmaSentryInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class PragmaSentryOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract has a safe locked pragma compiler setup")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names (always empty for file-level pragma checks)")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed pragma safety and compliance findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_PRAGMA_RISK, REJECTED_PRAGMA_RISK)")


# 3. Core Micro-Agent Class
class PiFloatingPragmaSentry:
    """Specialized Web3 micro-agent that audits Solidity contracts for floating or unsafe compiler pragmas."""

    def __init__(self) -> None:
        self.agent_name = "PiFloatingPragmaSentry"

    def audit_pragma(self, input_envelope: PragmaSentryInput) -> PragmaSentryOutput:
        """Autonomously audits Solidity contracts for floating pragma compiler configurations and stable locked version compliance."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all occurrences of pragma solidity
        pragma_matches = re.findall(r'pragma\s+solidity\s+([^;]+);', code)

        if not pragma_matches:
            vulnerable_funcs.append("file_header")
            flagged_findings.append(
                "Solidity file does not specify any 'pragma solidity' version. "
                "This leaves compiler choice completely unbound and highly unsafe."
            )
        else:
            for pragma_val in pragma_matches:
                pragma_val_clean = pragma_val.strip()

                # Mode 1: Floating Pragma Scan
                # A pragma is floating if it contains ^, >=, >, <=, < or does not lock a single specific version.
                is_floating = False
                if any(op in pragma_val_clean for op in ["^", ">", "<", ">=", "<="]):
                    is_floating = True

                if is_floating:
                    vulnerable_funcs.append("file_header")
                    flagged_findings.append(
                        f"Solidity file uses a floating or unbounded pragma: 'pragma solidity {pragma_val_clean};'. "
                        f"Floating pragmas allow compilation with untested/buggy compilers in production."
                    )

                # Mode 2: Locked Stable Pragma Auditor
                # Ensure the locked version is stable and not known to be severely buggy or excessively outdated (e.g. <0.8.0)
                # Parse out any digits/dots representation of version
                version_match = re.search(r'(\d+\.\d+\.\d+)', pragma_val_clean)
                if version_match:
                    version_str = version_match.group(1)
                    parts = [int(p) for p in version_str.split('.')]
                    if len(parts) >= 3:
                        major, minor, patch = parts[0], parts[1], parts[2]
                        if major == 0 and minor < 8:
                            flagged_findings.append(
                                f"Locked compiler version '{version_str}' is outdated and below 0.8.0. "
                                "Deploying with old compiler versions risks encountering known compiler bugs (e.g. storage overflow issues)."
                            )
                        # Specific known highly buggy compiler version check (e.g., 0.8.0 - 0.8.2 which had serious bugs)
                        if major == 0 and minor == 8 and patch in [0, 1, 2]:
                            flagged_findings.append(
                                f"Compiler version '{version_str}' contains severe known code generation bugs (e.g., ABI encoder v2 bugs). "
                                "Consider upgrading to at least 0.8.20."
                            )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_PRAGMA_RISK"
            else:
                status = "WARN_PRAGMA_RISK"
                is_secure = True

        return PragmaSentryOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
