from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ZK_PROOF_PUBLIC_INPUT_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_ZK_PROOF_PUBLIC_INPUT_STRICT_MODE", True))
        except Exception:
            pass
    return True


class ZKProofPublicInputVerifInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class ZKProofPublicInputVerifOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if public input verifications passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiZKProofPublicInputVerif:
    """Specialized ZK validation micro-agent that audits Solidity verifier contracts for unconstrained or missing public input assertions."""

    def __init__(self) -> None:
        self.agent_name = "PiZKProofPublicInputVerif"

    def audit_public_input(self, input_envelope: ZKProofPublicInputVerifInput) -> ZKProofPublicInputVerifOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions doing verifyProof calls
        # E.g. verifyProof, verifyZK
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)(?=\n\s*function|\Z)", code)

        for name, _args, body in func_blocks:
            if any(x in name.lower() for x in ["verifyproof", "verifyzk"]):
                # Check if public inputs array or parameter matches a verification requirement but is never checked or asserted
                # Look for calls to verifyProof(a, b, c, input) where input is unchecked. E.g. lacks checking that the input matches the target state
                # Let's check if the verifyProof call receives inputs, but there are no constraints/requirements matching input values in the body.
                if "input" in body or "publicInput" in body:
                    # Look for require or if checks on those input elements
                    has_input_validation = False
                    if re.search(r"(require\s*\(\s*input|require\s*\(\s*publicInput|assert\s*\(\s*input)", body):
                        has_input_validation = True
                    if re.search(r"(if\s*\(\s*input|if\s*\(\s*publicInput)", body):
                        has_input_validation = True

                    if not has_input_validation:
                        vulnerable_funcs.append(name)
                        flagged_findings.append(
                            f"ZK verifier caller function '{name}' handles public inputs but lacks matching require/assert "
                            f"checks to verify that the public inputs match the caller's expected state parameters. "
                            f"This can allow attackers to supply arbitrary public input arrays for valid proofs, bypassing system constraints."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ZK_PUBLIC_INPUT"
            else:
                status = "WARN_ZK_PUBLIC_INPUT"
                is_secure = True

        return ZKProofPublicInputVerifOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
