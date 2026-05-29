"""PiERC4626VaultGuard — Tokenized Vault Standard Compliance & Attack Surface Agent.

Dual-use micro-agent:
  Mode 1 (Vulnerability): Detects ERC-4626 attack vectors — first-depositor share
           inflation, rounding direction errors, and missing deposit/mint guards.
  Mode 2 (Compliance): Verifies all required ERC-4626 interface functions and
           events are present and correctly named.
"""

from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.utils import is_strict_mode

# ── Pydantic Envelopes ─────────────────────────────────────────────────────

class VaultGuardInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity vault contract source")
    check_level: str = Field(default="STRICT", description="STRICT or MEDIUM")


class VaultGuardOutput(BaseModel):
    is_compliant: bool = Field(..., description="True if no attack vectors or missing interface items found")
    attack_vectors: List[str] = Field(default_factory=list, description="Detected attack surface findings")
    missing_functions: List[str] = Field(default_factory=list, description="ERC-4626 required functions that are absent")
    rounding_violations: List[str] = Field(default_factory=list, description="Rounding direction errors detected")
    risk_score: float = Field(..., description="Risk score 0.0–100.0")
    status: str = Field(..., description="PASSED | WARN_VAULT_RISK | REJECTED_VAULT_RISK")


# ── ERC-4626 Required Interface ────────────────────────────────────────────

ERC4626_REQUIRED_FUNCTIONS = [
    "asset",
    "totalAssets",
    "convertToShares",
    "convertToAssets",
    "maxDeposit",
    "previewDeposit",
    "deposit",
    "maxMint",
    "mint",
    "maxWithdraw",
    "previewWithdraw",
    "withdraw",
    "maxRedeem",
    "previewRedeem",
    "redeem",
]

ERC4626_REQUIRED_EVENTS = ["Deposit", "Withdraw"]


# ── Core Agent ─────────────────────────────────────────────────────────────

class PiERC4626VaultGuard:
    """Audits ERC-4626 tokenized vault contracts for inflation attacks,
    rounding errors, and spec compliance."""

    def __init__(self) -> None:
        self.agent_name = "PiERC4626VaultGuard"

    def audit_vault(self, inp: VaultGuardInput) -> VaultGuardOutput:
        code = inp.solidity_code

        # Strip comments for clean analysis
        cleaned = re.sub(r"//[^\n]*", "", code)
        cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)

        attack_vectors: List[str] = []
        rounding_violations: List[str] = []
        missing_functions: List[str] = []

        is_vault = bool(
            re.search(r"\bERC4626\b|\bIVault\b|\btotalAssets\b|\bconvertToShares\b", code)
        )

        # ── Mode 1: Attack Surface Detection ──────────────────────────────

        # 1a. First-depositor share inflation protection
        # Safe vaults use virtual shares: totalSupply() + 10**decimals offset
        # or OpenZeppelin's _decimalsOffset() pattern
        has_virtual_shares = bool(
            re.search(
                r"_decimalsOffset\s*\(\s*\)|10\s*\*\*\s*decimals\(\s*\)|virtualShares|offset",
                cleaned,
            )
        )
        if is_vault and not has_virtual_shares:
            attack_vectors.append(
                "INFLATION ATTACK: No virtual shares protection detected. "
                "First depositor can donate assets to inflate share price, "
                "causing subsequent depositors to receive 0 shares. "
                "Add `_decimalsOffset()` override or virtual shares offset (OZ ERC4626 pattern)."
            )

        # 1b. Rounding direction errors in convertToShares / convertToAssets
        # convertToShares should round DOWN (mulDiv rounding toward 0 — favors vault)
        # convertToAssets should round DOWN (favors vault on withdrawals)
        # Flag any mulDivUp usage in these functions
        conv_shares_body = _extract_function_body(cleaned, "convertToShares")
        conv_assets_body = _extract_function_body(cleaned, "convertToAssets")

        if conv_shares_body and re.search(r"mulDivUp|Math\.ceilDiv|roundUp|Rounding\.Up\b", conv_shares_body):
            rounding_violations.append(
                "ROUNDING ERROR in convertToShares: rounds UP (favors depositor). "
                "ERC-4626 spec §3: convertToShares MUST round DOWN to protect the vault. "
                "Use mulDiv(..., Rounding.Down) or plain integer division."
            )

        if conv_assets_body and re.search(r"mulDivUp|Math\.ceilDiv|roundUp|Rounding\.Up\b", conv_assets_body):
            rounding_violations.append(
                "ROUNDING ERROR in convertToAssets: rounds UP (favors withdrawer). "
                "ERC-4626 spec §3: convertToAssets MUST round DOWN to protect the vault. "
                "Use mulDiv(..., Rounding.Down) or plain integer division."
            )

        # previewWithdraw / previewRedeem should round UP (to match actual withdraw cost)
        preview_withdraw_body = _extract_function_body(cleaned, "previewWithdraw")
        if preview_withdraw_body and not re.search(
            r"mulDivUp|Math\.ceilDiv|Rounding\.Up\b|roundUp", preview_withdraw_body
        ):
            rounding_violations.append(
                "ROUNDING RISK in previewWithdraw: does not appear to round UP. "
                "ERC-4626 spec §4: previewWithdraw MUST round UP (toward infinity) "
                "so callers are not surprised by needing more shares than previewed."
            )

        # 1c. Missing maxDeposit guard enforcement in deposit()
        deposit_body = _extract_function_body(cleaned, "deposit")
        if deposit_body and not re.search(r"maxDeposit\s*\(|require\s*\([^)]*max", deposit_body):
            attack_vectors.append(
                "MISSING maxDeposit GUARD: deposit() does not check maxDeposit(receiver). "
                "Deposits above capacity limits should revert. Violates ERC-4626 §3 invariant."
            )

        # 1d. Missing maxMint guard enforcement in mint()
        mint_body = _extract_function_body(cleaned, "mint")
        if mint_body and not re.search(r"maxMint\s*\(|require\s*\([^)]*max", mint_body):
            attack_vectors.append(
                "MISSING maxMint GUARD: mint() does not check maxMint(receiver). "
                "Mint above capacity should revert per ERC-4626 §3."
            )

        # ── Mode 2: ERC-4626 Interface Compliance ─────────────────────────
        for fn in ERC4626_REQUIRED_FUNCTIONS:
            # Check function definition exists (public/external)
            fn_pattern = re.compile(
                r"\bfunction\s+" + re.escape(fn) + r"\s*\(",
            )
            if not fn_pattern.search(cleaned):
                missing_functions.append(f"MISSING function: {fn}()")

        for ev in ERC4626_REQUIRED_EVENTS:
            ev_pattern = re.compile(r"\bevent\s+" + re.escape(ev) + r"\s*\(")
            if not ev_pattern.search(cleaned):
                missing_functions.append(f"MISSING event: {ev}")

        # ── Scoring & Status ───────────────────────────────────────────────
        is_compliant = (
            len(attack_vectors) == 0
            and len(rounding_violations) == 0
            and len(missing_functions) == 0
        )
        has_critical = len(attack_vectors) > 0 or len(rounding_violations) > 0

        risk_score = 0.0
        if has_critical:
            risk_score = 90.0
        elif missing_functions:
            risk_score = 40.0

        strict = is_strict_mode("PI_ERC4626_STRICT_MODE")
        status = "PASSED"
        if not is_compliant:
            if has_critical:
                status = "REJECTED_VAULT_RISK" if strict else "WARN_VAULT_RISK"
                if not strict:
                    is_compliant = True
            else:
                status = "WARN_VAULT_RISK"

        return VaultGuardOutput(
            is_compliant=is_compliant,
            attack_vectors=attack_vectors,
            missing_functions=missing_functions,
            rounding_violations=rounding_violations,
            risk_score=risk_score,
            status=status,
        )


# ── Utility ────────────────────────────────────────────────────────────────

def _extract_function_body(code: str, fn_name: str) -> str:
    """Return the body of the first matching function, or empty string."""
    pattern = re.compile(
        r"\bfunction\s+" + re.escape(fn_name) + r"\s*\([^)]*\)[^{]*\{",
    )
    m = pattern.search(code)
    if not m:
        return ""
    start = m.end() - 1  # position of opening {
    depth = 0
    for i in range(start, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[start:i + 1]
    return ""
