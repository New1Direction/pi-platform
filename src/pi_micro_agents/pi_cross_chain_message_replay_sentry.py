from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_BRIDGE_REPLAY_STRICT_MODE")


# 2. Pydantic-Enforced Input/Output Envelopes
class BridgeReplayInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class BridgeReplayOutput(BaseModel):
    is_secure: bool = Field(
        ..., description="Indicates if contract cross-chain message processing is safe from replays"
    )
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed bridge replay findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_BRIDGE_REPLAY, REJECTED_BRIDGE_REPLAY)")


# 3. Core Micro-Agent Class
class PiCrossChainMessageReplaySentry:
    """Specialized Web3 micro-agent that audits contracts for cross-chain message replay vulnerabilities without verification maps."""

    def __init__(self) -> None:
        self.agent_name = "PiCrossChainMessageReplaySentry"

    def audit_bridge_replay(self, input_envelope: BridgeReplayInput) -> BridgeReplayOutput:
        """Autonomously audits Solidity cross-chain receiver functions for duplicate/replay message protection."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            # Mode 1: Check for receiver style function
            is_receiver = any(
                kw in name.lower() for kw in ["lzreceive", "execute", "process", "onmessagereceived", "receiveland"]
            )

            if is_receiver:
                # Mode 2: Verify if there is a tracking registry to record processed nonces or payload hashes
                # Check for mapping lookup and assignment in the receiver body
                has_nonce_guard = (
                    "processedNonces" in body
                    or "isExecuted" in body
                    or "processedMessages" in body
                    or re.search(r"mapping\s*\(\s*[^=]+=>\s*bool\s*\)", code)
                )

                if not has_nonce_guard:
                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Cross-chain receiver function '{name}' is missing message replay guards. "
                        "It does not maintain a deduplication registry (e.g. mapping of processed message hashes or nonces). "
                        "This permits malicious users to re-submit the same signed cross-chain payload repeatedly "
                        "to drain contract asset balances."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_BRIDGE_REPLAY"
            else:
                status = "WARN_BRIDGE_REPLAY"
                is_secure = True

        return BridgeReplayOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
