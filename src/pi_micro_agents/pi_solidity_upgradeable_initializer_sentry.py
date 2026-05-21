from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_UPGRADE_INIT_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_UPGRADE_INIT_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class UpgradeableInitInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class UpgradeableInitOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract initializers are securely protected")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed upgradeable initialization findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_INITIALIZER_RISK, REJECTED_INITIALIZER_RISK)")


# 3. Core Micro-Agent Class
class PiSolidityUpgradeableInitializerSentry:
    """Specialized Web3 micro-agent that audits Solidity upgradeable contracts for uninitialized or unguarded implementation takeovers."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityUpgradeableInitializerSentry"

    def audit_upgradeable_initializer(self, input_envelope: UpgradeableInitInput) -> UpgradeableInitOutput:
        """Autonomously audits upgradeable contracts for safe initialization locks."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r'function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}', code)

        # Check if contract is upgradeable (usually imports Initializable or extends upgradeable base contracts)
        is_upgradeable = "Initializable" in code or "initializer" in code or "onlyInitializing" in code

        if is_upgradeable:
            # Check constructor block to ensure it disables initializers
            constructor_match = re.search(r'constructor\s*\((.*?)\)\s*\{([\s\S]*?)\}', code)
            if constructor_match:
                constructor_body = constructor_match.group(2)
                if "_disableInitializers" not in constructor_body:
                    vulnerable_funcs.append("constructor")
                    flagged_findings.append(
                        "Constructor is present in upgradeable contract but does not call '_disableInitializers()'. "
                        "This allows third parties to initialize the logic contract and execute self-destruct instructions."
                    )

            # Check all functions named initialize or similar to ensure they are guarded
            for name, args, body in func_blocks:
                if "initialize" in name.lower() and "function" in code:
                    # Initializer functions must contain the 'initializer' or 'onlyInitializing' modifiers
                    has_initializer_guard = "initializer" in code or "onlyInitializing" in code
                    # Let's check specifically in function definition or function body
                    # Better verification: checking if function definition has 'initializer' modifier
                    func_def_match = re.search(r'function\s+' + name + r'\s*\((.*?)\)[^{]*', code)
                    if func_def_match:
                        def_string = func_def_match.group(0)
                        if "initializer" not in def_string and "onlyInitializing" not in def_string:
                            vulnerable_funcs.append(name)
                            flagged_findings.append(
                                f"Upgradeable initialization function '{name}' is missing 'initializer' or 'onlyInitializing' guards. "
                                "This allows attackers to re-initialize and hijack implementation controls."
                            )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_INITIALIZER_RISK"
            else:
                status = "WARN_INITIALIZER_RISK"
                is_secure = True

        return UpgradeableInitOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
