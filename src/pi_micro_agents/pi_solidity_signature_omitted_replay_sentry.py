from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_SIGNATURE_OMITTED_REPLAY_STRICT_MODE")


class SignatureOmittedReplayInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level: STRICT, MEDIUM")


class SignatureOmittedReplayOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract hashing prevents signature replay")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings on signature replay risks")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSoliditySignatureOmittedReplaySentry:
    """Specialized Web3 micro-agent that audits EIP-712 hash calculation functions for omitting nonces or block.chainid parameters, creating signature replay vulnerabilities."""

    def __init__(self) -> None:
        self.agent_name = "PiSoliditySignatureOmittedReplaySentry"

    def audit_signature_replay(self, input_envelope: SignatureOmittedReplayInput) -> SignatureOmittedReplayOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all functions
        func_blocks = re.findall(r"function\s+([a-zA-Z0-9_]+)\s*\((.*?)\)[^{]*\{([\s\S]*?)\}", code)

        for name, _args, body in func_blocks:
            # Look for keccak256 hashing associated with signatures
            if (
                "keccak256" in body
                and ("abi.encode" in body or "abi.encodePacked" in body)
                and (
                    "signature" in name.lower()
                    or "hash" in name.lower()
                    or "permit" in name.lower()
                    or "verify" in name.lower()
                )
            ):
                # Check if it includes block.chainid or chainid
                has_chainid = "chainid" in body or "block.chainid" in body
                # Check if it includes nonce or nonces
                has_nonce = "nonce" in body or "nonces" in body

                if not has_chainid or not has_nonce:
                    missing_elements = []
                    if not has_chainid:
                        missing_elements.append("block.chainid")
                    if not has_nonce:
                        missing_elements.append("nonce")

                    vulnerable_funcs.append(name)
                    flagged_findings.append(
                        f"Function '{name}' hashes parameters for signature verification but lacks {', '.join(missing_elements)}. "
                        "Omitting chainid allows signature replay across different forks or EVM chains. "
                        "Omitting nonces allows double-spending/execution replay within the same contract."
                    )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 85.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_SIGNATURE_OMITTED_REPLAY"
            else:
                status = "WARN_SIGNATURE_OMITTED_REPLAY"
                is_secure = True

        return SignatureOmittedReplayOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
