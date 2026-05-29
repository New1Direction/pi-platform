from __future__ import annotations

import re
from typing import List, Tuple

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_PATCH_STRICT_MODE")


# 2. Static vulnerability inspection of target source code
def detect_unpatched_vulnerabilities(text: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0
    if not text:
        return 0.0, []

    # Heuristic smart contract vulnerabilities
    if re.search(r"\btx\.origin\b", text, re.IGNORECASE):
        violations.append("tx.origin authentication vulnerability")
        max_risk = max(max_risk, 90.0)

    if re.search(r"\bdelegatecall\b", text, re.IGNORECASE):
        violations.append("unprotected delegatecall vulnerability")
        max_risk = max(max_risk, 90.0)

    if re.search(r"selfdestruct\b|suicide\b", text, re.IGNORECASE):
        violations.append("critical selfdestruct capability found")
        max_risk = max(max_risk, 90.0)

    # Missing external call verification: only trigger if a line has .call without assignment or verification guards
    if ".call" in text:
        for line in text.splitlines():
            if ".call" in line and ";" in line:
                if "=" not in line and "require" not in line and "assert" not in line:
                    violations.append("missing external call verification")
                    max_risk = max(max_risk, 90.0)
                    break

    # Check for missing reentrancy guard modifiers in functions making call transfers
    if ".call" in text and "nonReentrant" not in text:
        violations.append("missing nonReentrant guard on external call function")
        max_risk = max(max_risk, 80.0)

    return max_risk, violations


# 3. Pydantic-Enforced Input/Output Envelopes
class PatchInput(BaseModel):
    vulnerability_id: str
    file_path: str
    source_code: str
    severity: str = "High"


class PatchOutput(BaseModel):
    patched_code: str
    diff: str
    remediation_steps: List[str] = Field(default_factory=list)
    success: bool


# 4. Core Micro-Agent Class
class PiPatchSynthesizer:
    """Automated hotfix generator that patches found vulnerabilities in smart contracts."""

    def __init__(self) -> None:
        self.agent_name = "PiPatchSynthesizer"

    def synthesize_remediation(self, input_envelope: PatchInput) -> PatchOutput:
        """Synthesizes code corrections for flagged high-severity smart contract flaws."""
        code = input_envelope.source_code
        remedy_steps = []
        patched = code
        success = False

        # Apply basic heuristic patches for vulnerability vectors

        # A. Patch tx.origin -> msg.sender
        if "tx.origin" in code:
            patched = re.sub(r"\btx\.origin\b", "msg.sender", patched)
            remedy_steps.append("Replaced insecure 'tx.origin' authentication checks with 'msg.sender'.")
            success = True

        # B. Check for call success verification and patch if missing
        patched_lines = []
        applied_call_patch = False
        for line in patched.splitlines():
            if ".call" in line and ";" in line:
                if "=" not in line and "require" not in line and "assert" not in line:
                    indent = line[: len(line) - len(line.lstrip())]
                    stmt = line.strip().rstrip(";")
                    patched_line = f'{indent}(bool success, ) = {stmt};\n{indent}require(success, "Transfer failed");'
                    patched_lines.append(patched_line)
                    applied_call_patch = True
                    continue
            patched_lines.append(line)

        if applied_call_patch:
            patched = "\n".join(patched_lines)
            remedy_steps.append("Wrapped unverified external call in require statement to prevent silent failure.")
            success = True

        # Generate a unified Git-style diff
        diff_lines = []
        if code != patched:
            for c_line, p_line in zip(code.splitlines(), patched.splitlines()):
                if c_line != p_line:
                    diff_lines.append(f"- {c_line}")
                    diff_lines.append(f"+ {p_line}")
        diff = "\n".join(diff_lines)

        # In strict mode, if we found critical flaws but could not patch them, we reject compilation
        is_strict = is_strict_mode()
        risk, violations = detect_unpatched_vulnerabilities(patched)

        if is_strict and risk >= 90.0:
            # Still highly vulnerable post-patch attempt
            success = False
            remedy_steps.append("Failed safety compilation due to remaining unpatched vulnerabilities.")

        return PatchOutput(patched_code=patched, diff=diff, remediation_steps=remedy_steps, success=success)
