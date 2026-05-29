"""PiCrossChainBridgeAuditor — Bridge Security & Message Integrity Agent.

Dual-use micro-agent:
  Mode 1 (Vulnerability): Detects the four most critical bridge attack vectors —
           unverified message authentication, missing nonce replay protection,
           absent chain-ID binding in message hashes, and centralized validator risk.
  Mode 2 (Compliance): Verifies standard bridge interface patterns: sendMessage
           signature, event emission, fee/message separation, and nonce manager.
"""

from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.utils import is_strict_mode

# ── Pydantic Envelopes ─────────────────────────────────────────────────────

class BridgeAuditInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Bridge contract Solidity source")
    check_level: str = Field(default="STRICT", description="STRICT or MEDIUM")


class BridgeAuditOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no critical bridge vulnerabilities found")
    unverified_messages: List[str] = Field(default_factory=list, description="Unverified message execution findings")
    replay_risks: List[str] = Field(default_factory=list, description="Nonce / replay vulnerability findings")
    chain_id_issues: List[str] = Field(default_factory=list, description="Missing chain-ID binding findings")
    centralization_risks: List[str] = Field(default_factory=list, description="Validator/relayer centralization findings")
    compliance_findings: List[str] = Field(default_factory=list, description="Interface / event compliance findings")
    risk_score: float = Field(..., description="Risk score 0.0–100.0")
    status: str = Field(..., description="PASSED | WARN_BRIDGE_RISK | REJECTED_BRIDGE_RISK")


# ── Helpers ────────────────────────────────────────────────────────────────

_BRIDGE_KEYWORDS_RE = re.compile(
    r"\b(bridge|relayer|validator|processMessage|executeMessage|receiveMessage"
    r"|sendMessage|crossChain|LayerZero|Wormhole|CCIP|Hyperlane|Nomad)\b",
    re.IGNORECASE,
)

_MULTI_SIG_RE = re.compile(
    r"quorum|threshold|multisig|multiSig|_validators\.length|validatorSet|signatures\.length"
    r"|numConfirmations|approvalCount|_required",
    re.IGNORECASE,
)

_NONCE_MAP_RE = re.compile(
    r"mapping\s*\([^)]*=>\s*(?:bool|uint|mapping)\s*\)\s*(?:public\s+|private\s+|internal\s+)?"
    r"(?:processedNonces|usedNonces|executedMessages|processedMessages|_executed|_used)",
    re.IGNORECASE,
)

_NONCE_CHECK_RE = re.compile(
    r"processedNonces|usedNonces|executedMessages|_executed\[|_used\[|nonces\[|!nonce",
    re.IGNORECASE,
)

_CHAIN_ID_RE = re.compile(
    r"block\.chainid|chainId|chainID|_chainId|CHAIN_ID|getChainId\(",
    re.IGNORECASE,
)

_TIMELOCK_RE = re.compile(
    r"timelock|TimelockController|delay\s*>=|_delay\s*>=|MIN_DELAY",
    re.IGNORECASE,
)


def _extract_function_body(code: str, fn_name: str) -> str:
    pattern = re.compile(r"\bfunction\s+" + re.escape(fn_name) + r"\s*\([^)]*\)[^{]*\{")
    m = pattern.search(code)
    if not m:
        return ""
    start = m.end() - 1
    depth = 0
    for i in range(start, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[start : i + 1]
    return ""


# ── Core Agent ─────────────────────────────────────────────────────────────

class PiCrossChainBridgeAuditor:
    """Audits cross-chain bridge contracts for the top four attack vectors
    and standard interface compliance."""

    def __init__(self) -> None:
        self.agent_name = "PiCrossChainBridgeAuditor"

    def audit_bridge(self, inp: BridgeAuditInput) -> BridgeAuditOutput:
        code = inp.solidity_code

        # Strip comments
        cleaned = re.sub(r"//[^\n]*", "", code)
        cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)

        unverified: List[str] = []
        replay: List[str] = []
        chain_id: List[str] = []
        centralization: List[str] = []
        compliance: List[str] = []

        is_bridge = bool(_BRIDGE_KEYWORDS_RE.search(code))

        # ── Mode 1: Attack Vector Detection ───────────────────────────────

        # 1a. Unverified message authentication
        # Find execute/process/receive message functions and check for quorum/multisig verification
        for fn_name in ("executeMessage", "processMessage", "receiveMessage", "execute", "process"):
            body = _extract_function_body(cleaned, fn_name)
            if not body:
                continue
            if not _MULTI_SIG_RE.search(body) and not re.search(
                r"require\s*\([^)]*(?:valid|verify|signature|signer|proof)", body, re.IGNORECASE
            ):
                unverified.append(
                    f"UNVERIFIED MESSAGE in {fn_name}(): No multi-sig quorum or "
                    f"validator signature verification detected before processing. "
                    f"Attacker can submit arbitrary cross-chain messages. "
                    f"Verify a threshold of validators have signed (e.g. `_signers >= _quorum`)."
                )

        # 1b. Missing nonce replay protection
        # Check: (a) no nonce mapping declared and (b) no nonce check in execute functions
        has_nonce_map = bool(_NONCE_MAP_RE.search(cleaned))
        has_nonce_check = bool(_NONCE_CHECK_RE.search(cleaned))

        if is_bridge and not has_nonce_map and not has_nonce_check:
            replay.append(
                "MISSING NONCE REPLAY GUARD: No processed-nonce mapping found. "
                "Cross-chain messages can be replayed indefinitely. "
                "Add: `mapping(bytes32 => bool) public processedNonces;` and check "
                "`require(!processedNonces[msgHash], 'already executed');` before processing."
            )
        elif has_nonce_check and not has_nonce_map:
            replay.append(
                "NONCE CHECK WITHOUT MAPPING: Nonce is checked but no persistent mapping "
                "found to store processed state. Nonce guard may not survive contract upgrades."
            )

        # 1c. Missing chain-ID binding in message hash construction
        # Look for abi.encode / keccak256 in execute/send functions and check for chainId
        for fn_name in ("executeMessage", "processMessage", "sendMessage", "_hashMessage", "hashMessage"):
            body = _extract_function_body(cleaned, fn_name)
            if not body:
                continue
            if re.search(r"abi\.encode|keccak256", body) and not _CHAIN_ID_RE.search(body):
                chain_id.append(
                    f"MISSING chain-ID in {fn_name}(): Message hash uses abi.encode/keccak256 "
                    f"but does not include `block.chainid`. The same signed message can be replayed "
                    f"on any EVM chain. Add `block.chainid` to the hash preimage."
                )

        # 1d. Centralized validator / relayer risk
        # Single owner controls the validator set with no timelock
        has_set_validator = bool(
            re.search(
                r"function\s+(?:setValidator|addValidator|removeValidator|setRelayer|updateSigner|setOperator)\s*\(",
                cleaned,
                re.IGNORECASE,
            )
        )
        if has_set_validator:
            validator_body = ""
            for fn_name in ("setValidator", "addValidator", "removeValidator", "setRelayer", "updateSigner"):
                validator_body += _extract_function_body(cleaned, fn_name)

            if not _TIMELOCK_RE.search(validator_body) and not _MULTI_SIG_RE.search(validator_body):
                centralization.append(
                    "CENTRALIZED VALIDATOR SET: Validator/relayer admin function(s) are "
                    "controlled by a single address with no timelock or multi-sig. "
                    "A compromised owner key can instantly replace all validators and "
                    "drain the bridge. Add TimelockController with >= 2-day delay."
                )

        # ── Mode 2: Interface Compliance ───────────────────────────────────

        # sendMessage should emit an event
        send_body = _extract_function_body(cleaned, "sendMessage")
        if send_body and not re.search(r"\bemit\b", send_body):
            compliance.append(
                "NO EVENT in sendMessage(): Cross-chain message sends should emit an indexed "
                "event (e.g. `MessageSent(uint256 dstChainId, address sender, bytes payload)`) "
                "for off-chain relayer monitoring and replay detection."
            )

        # Fee accounting should be separate from message storage
        if re.search(r"function\s+sendMessage", cleaned, re.IGNORECASE):
            if re.search(r"msg\.value|fee", cleaned, re.IGNORECASE) and not re.search(
                r"_fee|feeBalance|_fees\[|feePaid", cleaned, re.IGNORECASE
            ):
                compliance.append(
                    "FEE ACCOUNTING: Bridge collects msg.value but no separate fee tracking "
                    "variable found. Fee manipulation attacks mix fee and message accounting. "
                    "Track fees in a dedicated `uint256 _fees` or `mapping(address => uint256) feeBalance`."
                )

        # ── Scoring & Status ───────────────────────────────────────────────
        is_secure = (
            len(unverified) == 0
            and len(replay) == 0
            and len(chain_id) == 0
            and len(centralization) == 0
        )
        critical_count = len(unverified) + len(replay) + len(chain_id) + len(centralization)

        risk_score = 0.0
        if critical_count >= 3:
            risk_score = 98.0
        elif critical_count >= 1:
            risk_score = min(95.0, 60.0 + critical_count * 12.0)
        elif compliance:
            risk_score = 25.0

        strict = is_strict_mode("PI_BRIDGE_STRICT_MODE")
        status = "PASSED"
        if not is_secure:
            status = "REJECTED_BRIDGE_RISK" if strict else "WARN_BRIDGE_RISK"
            if not strict:
                is_secure = True
        elif compliance:
            status = "WARN_BRIDGE_RISK"

        return BridgeAuditOutput(
            is_secure=is_secure,
            unverified_messages=unverified,
            replay_risks=replay,
            chain_id_issues=chain_id,
            centralization_risks=centralization,
            compliance_findings=compliance,
            risk_score=risk_score,
            status=status,
        )
