from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_COMPILER_BUGS_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_COMPILER_BUGS_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class CompilerBugsInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class CompilerBugsOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if compiler setup is free from severe compiler-level defects")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names (file-level checks)")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed compiler bug safety findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_COMPILER_RISK, REJECTED_COMPILER_RISK)")


# 3. Core Micro-Agent Class
class PiSolidityCompilerBugsSentry:
    """Specialized Web3 micro-agent that audits contracts for locked pragmas matching known buggy compiler releases."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityCompilerBugsSentry"

    def audit_compiler_bugs(self, input_envelope: CompilerBugsInput) -> CompilerBugsOutput:
        """Autonomously audits Solidity compiler choices against critical CVE profiles and compiler bug reports."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find pragma statements
        pragma_matches = re.findall(r'pragma\s+solidity\s+([^;]+);', code)

        for pragma_val in pragma_matches:
            pragma_val_clean = pragma_val.strip()
            version_match = re.search(r'(\d+\.\d+\.\d+)', pragma_val_clean)
            if version_match:
                version_str = version_match.group(1)
                parts = [int(p) for p in version_str.split('.')]
                if len(parts) >= 3:
                    major, minor, patch = parts[0], parts[1], parts[2]

                    # Specific Yul Optimizer severe memory bug releases
                    if major == 0 and minor == 8 and patch in [13, 14, 15]:
                        vulnerable_funcs.append("file_header")
                        flagged_findings.append(
                            f"Compiler version '{version_str}' suffers from a critical Yul Optimizer bug. "
                            "When optimizing memory writes, the compiler can incorrectly overwrite storage offsets, "
                            "leading to arbitrary state corruption."
                        )

                    # Dynamic size array lookup bug in 0.8.3 - 0.8.7
                    if major == 0 and minor == 8 and patch in [3, 4, 5, 6, 7]:
                        vulnerable_funcs.append("file_header")
                        flagged_findings.append(
                            f"Compiler version '{version_str}' is affected by a severe ABI encoder v2 "
                            "memory allocation bug when handling dynamic multi-dimensional arrays."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_COMPILER_RISK"
            else:
                status = "WARN_COMPILER_RISK"
                is_secure = True

        return CompilerBugsOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
