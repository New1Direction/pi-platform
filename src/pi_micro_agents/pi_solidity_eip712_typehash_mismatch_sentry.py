from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_EIP712_TYPEHASH_STRICT_MODE")


class EIP712TypehashMismatchInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class EIP712TypehashMismatchOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if EIP-712 typehash alignment checks passed")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function/variable names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiSolidityEIP712TypehashMismatchSentry:
    """Specialized Web3 micro-agent that audits Solidity EIP-712 TYPEHASH declarations to ensure perfect struct layout alignment."""

    def __init__(self) -> None:
        self.agent_name = "PiSolidityEIP712TypehashMismatchSentry"

    def audit_typehash_alignment(self, input_envelope: EIP712TypehashMismatchInput) -> EIP712TypehashMismatchOutput:
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        # Find all structs defined in Solidity
        structs = re.findall(r"struct\s+([a-zA-Z0-9_]+)\s*\{([\s\S]*?)\}", code)
        struct_map = {}
        for sname, sbody in structs:
            # Parse variables: e.g. address from;
            vars_list = re.findall(r"([a-zA-Z0-9_\[\]]+)\s+([a-zA-Z0-9_]+)\s*;", sbody)
            struct_map[sname] = [(vtype.strip(), vname.strip()) for vtype, vname in vars_list]

        # Find all TYPEHASH constants/variables declared in Solidity, e.g. keccak256("Mail(address from,address to,string contents)")
        typehashes = re.findall(r'([a-zA-Z0-9_]+TYPEHASH[a-zA-Z0-9_]*)\s*=.*keccak256\s*\(\s*"([^"]+)"\s*\)', code)

        for th_name, signature in typehashes:
            # Extract struct name and params from signature, e.g. "Mail(address from,address to,string contents)"
            sig_match = re.match(r"([a-zA-Z0-9_]+)\s*\(([^)]*)\)", signature)
            if sig_match:
                sname = sig_match.group(1)
                sig_params_raw = sig_match.group(2)
                sig_params = [p.strip() for p in sig_params_raw.split(",") if p.strip()]

                # Compare with defined struct variables if the struct exists in parsed mapping
                if sname in struct_map:
                    expected_vars = struct_map[sname]
                    # Format expected vars as strings "type name"
                    expected_params = [f"{vtype} {vname}" for vtype, vname in expected_vars]

                    # Check for exact alignment of parameter counts and exact matching
                    mismatch = False
                    if len(sig_params) != len(expected_params):
                        mismatch = True
                    else:
                        for sp, ep in zip(sig_params, expected_params):
                            # Normalize spacing
                            sp_norm = " ".join(sp.split())
                            ep_norm = " ".join(ep.split())
                            if sp_norm != ep_norm:
                                mismatch = True
                                break

                    if mismatch:
                        vulnerable_funcs.append(th_name)
                        flagged_findings.append(
                            f"EIP-712 TYPEHASH constant '{th_name}' signature definition '{signature}' does not match "
                            f"the actual Solidity struct '{sname}' variables: {', '.join(expected_params)}. "
                            f"This mismatch breaks structured signature verification."
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 80.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_TYPEHASH_MISMATCH"
            else:
                status = "WARN_TYPEHASH_MISMATCH"
                is_secure = True

        return EIP712TypehashMismatchOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
