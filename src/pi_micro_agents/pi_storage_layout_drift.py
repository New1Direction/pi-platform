"""PiStorageLayoutDrift — Upgradeable Contract Storage Slot Drift Sentinel.

Dual-use micro-agent:
  Mode 1 (Vulnerability): Detects storage layout collisions between two contract
           versions that would silently corrupt proxy storage on upgrade.
  Mode 2 (Compliance): Audits OZ-style __gap padding and initializer guards
           to verify the contract follows the upgradeable contract standard.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from pydantic import BaseModel, Field

from pi_micro_agents.utils import is_strict_mode

# ── Pydantic Envelopes ─────────────────────────────────────────────────────


class StorageDriftInput(BaseModel):
    file_path: str = Field(..., description="Primary Solidity source file path")
    solidity_code: str = Field(..., description="Current contract version source")
    previous_code: str = Field(
        default="",
        description="Previous contract version source for drift comparison (optional)",
    )
    check_level: str = Field(default="STRICT", description="STRICT or MEDIUM")


class StorageDriftOutput(BaseModel):
    is_safe: bool = Field(..., description="True if no storage drift or gap violations found")
    drifted_slots: List[str] = Field(default_factory=list, description="Slot collision / drift findings")
    compliance_findings: List[str] = Field(default_factory=list, description="Gap / initializer compliance findings")
    risk_score: float = Field(..., description="Risk score 0.0–100.0")
    status: str = Field(..., description="PASSED | WARN_STORAGE_RISK | REJECTED_STORAGE_RISK")


# ── Helpers ────────────────────────────────────────────────────────────────

_STATE_VAR_RE = re.compile(
    r"^\s*(?!\/\/)(?:(?:public|private|internal|external|constant|immutable|override)\s+)*"
    r"(\w[\w\[\]<>, ]*?)\s+(?:public|private|internal|constant|immutable|override\s+)*(\w+)\s*[;=]",
    re.MULTILINE,
)

_MAPPING_RE = re.compile(
    r"^\s*mapping\s*\(",
    re.MULTILINE,
)

_GAP_RE = re.compile(
    r"uint256\s*\[\s*(\d+)\s*\]\s+(?:private\s+)?__gap\s*;",
)

_INITIALIZER_RE = re.compile(
    r"\binitializer\b|\b__init\b|\bInitializable\b",
)

_CONSTRUCTOR_INIT_RE = re.compile(
    r"\bconstructor\b[^{]*\{[^}]*=\s*[^;]+;",
    re.DOTALL,
)


def _extract_state_vars(code: str) -> List[Tuple[int, str, str]]:
    """Return ordered list of (slot_index, type, name) from contract state vars.

    Strips comments and function bodies first to avoid false matches inside
    function bodies.
    """
    # Strip single-line comments
    cleaned = re.sub(r"//[^\n]*", "", code)
    # Strip multi-line comments
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)

    # Extract only the contract-level scope (between first { and matching })
    brace_start = cleaned.find("{")
    if brace_start == -1:
        return []

    # Walk to find outer contract body (skip function bodies by counting braces)
    depth = 0
    contract_body_lines = []
    in_function = False
    fn_depth = 0
    lines = cleaned[brace_start:].split("\n")

    for line in lines:
        opens = line.count("{")
        closes = line.count("}")
        if depth == 1 and (re.search(r"\bfunction\b|\bconstructor\b|\bmodifier\b|\breceive\b|\bfallback\b", line)):
            in_function = True
            fn_depth = 0

        if in_function:
            fn_depth += opens - closes
            if fn_depth <= 0:
                in_function = False
        else:
            contract_body_lines.append(line)

        depth += opens - closes

    contract_body = "\n".join(contract_body_lines)

    vars_found: List[Tuple[int, str, str]] = []
    slot = 0
    for match in _STATE_VAR_RE.finditer(contract_body):
        var_type = match.group(1).strip()
        var_name = match.group(2).strip()
        # Skip event/error definitions slipping through
        if var_type in ("event", "error", "struct", "mapping", "enum", "function"):
            continue
        vars_found.append((slot, var_type, var_name))
        slot += 1

    return vars_found


# ── Core Agent ─────────────────────────────────────────────────────────────


class PiStorageLayoutDrift:
    """Detects upgradeable contract storage slot drift and gap compliance violations."""

    def __init__(self) -> None:
        self.agent_name = "PiStorageLayoutDrift"

    def audit_storage(self, inp: StorageDriftInput) -> StorageDriftOutput:
        code = inp.solidity_code
        prev_code = inp.previous_code
        drifted: List[str] = []
        compliance: List[str] = []

        # ── Mode 1: Storage Slot Drift (only when previous version provided) ──
        if prev_code.strip():
            current_vars = _extract_state_vars(code)
            previous_vars = _extract_state_vars(prev_code)

            # Build lookup: name → slot index for each version
            prev_by_name = {name: (slot, vtype) for slot, vtype, name in previous_vars}

            for slot, vtype, name in current_vars:
                if name == "__gap":
                    continue  # gaps intentionally shift and resize during upgrades
                if name in prev_by_name:
                    old_slot, old_type = prev_by_name[name]
                    if old_slot != slot:
                        drifted.append(
                            f"SLOT DRIFT: '{name}' moved from slot {old_slot} → {slot}. "
                            f"Any proxy pointing to the old layout will read corrupted state."
                        )
                    if old_type != vtype:
                        drifted.append(
                            f"TYPE CHANGE: '{name}' changed type '{old_type}' → '{vtype}'. "
                            f"Storage encoding mismatch will corrupt proxy reads."
                        )

            # Detect removed variables (slot vacated, shifts everything after)
            current_names = {name for _, _, name in current_vars}
            for slot, vtype, name in previous_vars:
                if name not in current_names and name != "__gap":
                    drifted.append(
                        f"REMOVED VAR: '{name}' (slot {slot}, type {vtype}) was deleted. "
                        f"All variables after this slot are now shifted — proxy storage is corrupted."
                    )

        # ── Mode 2: OZ Upgradeable Gap Compliance ─────────────────────────
        cleaned = re.sub(r"//[^\n]*", "", code)
        cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)

        # Check for __gap
        gap_match = _GAP_RE.search(cleaned)
        is_upgradeable = bool(re.search(r"\bUpgradeable\b|\bInitializable\b|\bUUPS\b|\bTransparentUpgradeable\b", code))

        if is_upgradeable and not gap_match:
            compliance.append(
                "MISSING __gap: Upgradeable contract does not declare a storage gap "
                "`uint256[N] __gap;`. Without a gap, adding state variables in a parent "
                "contract will shift child slots. Standard minimum is uint256[50] __gap."
            )
        elif gap_match:
            gap_size = int(gap_match.group(1))
            if gap_size < 10:
                compliance.append(
                    f"UNDERSIZED __gap: Gap is only {gap_size} slots. "
                    f"OpenZeppelin recommends at least 50 slots to leave room for future state variables."
                )

        # Check for constructor initializing state (bypassed by proxy)
        if is_upgradeable:
            if _CONSTRUCTOR_INIT_RE.search(cleaned):
                compliance.append(
                    "CONSTRUCTOR STATE INIT: Upgradeable contract has state variable "
                    "assignments inside the constructor. These are ignored by proxy storage — "
                    "all initialization must go in an `initialize()` function guarded by `initializer`."
                )

            if not _INITIALIZER_RE.search(code):
                compliance.append(
                    "MISSING initializer: Upgradeable contract has no `initializer` modifier "
                    "or `Initializable` import. The proxy's initialize() function could be "
                    "called multiple times by anyone."
                )

        # ── Scoring & Status ───────────────────────────────────────────────
        is_safe = len(drifted) == 0
        risk_score = 0.0
        if drifted:
            risk_score = 95.0
        elif compliance:
            risk_score = 50.0

        strict = is_strict_mode("PI_STORAGE_DRIFT_STRICT_MODE")
        status = "PASSED"
        if not is_safe:
            status = "REJECTED_STORAGE_RISK" if strict else "WARN_STORAGE_RISK"
            if not strict:
                is_safe = True
        elif compliance and strict:
            status = "WARN_STORAGE_RISK"

        return StorageDriftOutput(
            is_safe=is_safe,
            drifted_slots=drifted,
            compliance_findings=compliance,
            risk_score=risk_score,
            status=status,
        )
