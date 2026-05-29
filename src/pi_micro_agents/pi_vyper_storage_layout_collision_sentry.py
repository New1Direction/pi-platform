from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_VYPER_STORAGE_COLLISION_STRICT_MODE")


class VyperStorageCollisionInput(BaseModel):
    file_path: str = Field(..., description="Vyper source file path")
    vyper_code: str = Field(..., description="Vyper source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class VyperStorageCollisionOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Vyper storage collision checks passed")
    vulnerable_variables: List[str] = Field(default_factory=list, description="Vulnerable variable names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiVyperStorageLayoutCollisionSentry:
    """Specialized Web3 micro-agent that audits Vyper upgradeable contracts to ensure storage layout alignment is maintained."""

    def __init__(self) -> None:
        self.agent_name = "PiVyperStorageLayoutCollisionSentry"

    def audit_vyper_storage_collision(self, input_envelope: VyperStorageCollisionInput) -> VyperStorageCollisionOutput:
        code = input_envelope.vyper_code
        vulnerable_vars = []
        flagged_findings = []

        # Find all state variable declarations in Vyper
        # Vyper declarations: var_name: public(type) or var_name: type
        lines = code.splitlines()
        state_vars = []

        # Parse global state variables (which are defined outside of functions/def statements)
        in_fn = False
        for line_num, line in enumerate(lines, 1):
            clean_line = line.strip()
            if not clean_line or clean_line.startswith("#"):
                continue

            # Detect start of a function block in Vyper
            if clean_line.startswith("def ") or clean_line.startswith("@"):
                in_fn = True
                continue

            if in_fn:
                # If indentation is 0 and it starts a new block, we might have left function scope
                if line.startswith("def ") or line.startswith("@"):
                    in_fn = True
                elif not line.startswith(" ") and not line.startswith("\t") and ":" in clean_line:
                    # Variable declared outside functions
                    in_fn = False

            if not in_fn:
                match = re.match(r"^([a-zA-Z0-9_]+)\s*:\s*([^#\n]+)", clean_line)
                if match:
                    var_name = match.group(1)
                    var_type = match.group(2).strip()
                    # Skip constant or immutable variable decorations
                    if "constant" not in var_type and "immutable" not in var_type:
                        state_vars.append((var_name, var_type, line_num))

        # Under upgradeable proxy architectures, changing the order of state variables or adding them
        # in front/middle triggers storage slot alignment collisions.
        # Check if any new variable is prefixed or placed in an unsafe layout pattern.
        # A common vulnerability pattern is appending variables in-between older declarations.
        # Here we look for state variables defined with names ending in '_upgrade' or '_v2' but not defined at the end of the state variables list.
        for idx, (var_name, _var_type, line_num) in enumerate(state_vars):
            if "_v2" in var_name or "_upgrade" in var_name or "new_" in var_name:
                # If this upgraded variable is NOT at the end of the state variable declarations list, it causes slot collisions
                if idx < len(state_vars) - 1:
                    # Check if subsequent variables are older declarations (do not have _v2 or _upgrade or new_ in their names)
                    older_found = False
                    for next_idx in range(idx + 1, len(state_vars)):
                        next_name = state_vars[next_idx][0]
                        if "_v2" not in next_name and "_upgrade" not in next_name and "new_" not in next_name:
                            older_found = True

                    if older_found:
                        vulnerable_vars.append(var_name)
                        flagged_findings.append(
                            f"State variable '{var_name}' at line {line_num} contains upgrade-like markers but is defined "
                            f"prior to older state variable definitions in the layout list. In upgradeable Vyper contracts, "
                            f"declaring upgraded state variables out-of-order alters layout mapping, causing total "
                            f"storage corruption slots collision."
                        )

        is_secure = len(vulnerable_vars) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_VYPER_STORAGE_COLLISION"
            else:
                status = "WARN_VYPER_STORAGE_COLLISION"
                is_secure = True

        return VyperStorageCollisionOutput(
            is_secure=is_secure,
            vulnerable_variables=vulnerable_vars,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
