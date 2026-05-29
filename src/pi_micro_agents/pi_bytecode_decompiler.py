from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_BYTECODE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_BYTECODE_STRICT_MODE", True))
        except Exception:
            pass
    return True

# 2. Pydantic-Enforced Input/Output Envelopes
class BytecodeDecompilerInput(BaseModel):
    file_path: str = Field(..., description="Solidity or bytecode source file path")
    solidity_code: str = Field(..., description="Solidity code or raw EVM bytecode string")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")

class BytecodeDecompilerOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if bytecode/assembly is free from safety issues")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed line and violation findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_BYTECODE_VULNERABILITY, REJECTED_BYTECODE_VULNERABILITY)")

# Helper to check if string is raw EVM bytecode
def is_raw_bytecode(code: str) -> bool:
    cleaned = re.sub(r'\s+', '', code).lower()
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    return bool(re.match(r'^[0-9a-f]+$', cleaned)) and len(cleaned) >= 10

# 3. Core Micro-Agent Class
class PiBytecodeDecompiler:
    """Specialized Web3 micro-agent that audits EVM bytecode strings and Solidity inline assembly for security issues and gas efficiency."""

    def __init__(self) -> None:
        self.agent_name = "PiBytecodeDecompiler"

    def audit_bytecode(self, input_envelope: BytecodeDecompilerInput) -> BytecodeDecompilerOutput:
        """Autonomously audits Solidity inline assembly and raw EVM bytecode."""
        code = input_envelope.solidity_code
        vulnerable_funcs = []
        flagged_findings = []

        if is_raw_bytecode(code):
            # Mode 1: Raw EVM Bytecode Threat Audit
            bytecode_hex = re.sub(r'\s+', '', code).lower()
            if bytecode_hex.startswith("0x"):
                bytecode_hex = bytecode_hex[2:]

            # Scan for selfdestruct (ff) or delegatecall (f4) opcodes
            # In bytecode, these appear as standalone instructions or within patterns.
            # We will flag them as critical threats if found in raw bytecode.
            if "ff" in bytecode_hex:
                vulnerable_funcs.append("raw_bytecode")
                flagged_findings.append(
                    "Raw EVM bytecode contains the SELFDESTRUCT opcode (0xff) which can cause sudden contract destruction."
                )
            if "f4" in bytecode_hex:
                vulnerable_funcs.append("raw_bytecode")
                flagged_findings.append(
                    "Raw EVM bytecode contains the DELEGATECALL opcode (0xf4) which poses arbitrary execution hazards."
                )
        else:
            # Mode 2: Solidity Inline Assembly Audit & Gas Efficiency Check
            # Clean comments
            code_clean = re.sub(r'//.*', '', code)
            code_clean = re.sub(r'/\*.*?\*/', '', code_clean, flags=re.DOTALL)

            # Find inline assembly blocks: assembly { ... }
            assembly_matches = re.finditer(r'\bassembly\s*\{([^}]*)\}', code_clean)
            for i, match in enumerate(assembly_matches):
                block_content = match.group(1)
                start_idx = match.start()
                start_line = code[:start_idx].count('\n') + 1

                # Check for selfdestruct or delegatecall inside assembly block
                if "selfdestruct(" in block_content or "suicide(" in block_content:
                    vulnerable_funcs.append(f"assembly_block_{i+1}")
                    flagged_findings.append(
                        f"Inline assembly block on Line {start_line} contains a selfdestruct opcode call."
                    )
                if "delegatecall(" in block_content:
                    # Let's see if it's safe (e.g. check for proxy storage EIP-1967 slot reference in the contract)
                    if "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc" not in code_clean:
                        vulnerable_funcs.append(f"assembly_block_{i+1}")
                        flagged_findings.append(
                            f"Inline assembly block on Line {start_line} uses delegatecall without EIP-1967 slot safety."
                        )

                # Compliance/Optimization: Check for gas efficiency recommendations (e.g. recommend assembly memory checks)
                if "mstore(" in block_content and "0x40" in block_content:
                    # Writing to free memory pointer is valid, but let's warn if there are manual writes below 0x40 (scratch space)
                    bad_scratch_match = re.search(r'mstore\(\s*(0x[0-1]?[0-9a-fA-F]|0|1|2|3)[^,]*\s*,', block_content)
                    if bad_scratch_match:
                        flagged_findings.append(
                            f"Optimization warning: Inline assembly block on Line {start_line} writes to reserved scratch space memory: {bad_scratch_match.group(0)}"
                        )

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 90.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_BYTECODE_VULNERABILITY"
            else:
                status = "WARN_BYTECODE_VULNERABILITY"
                is_secure = True

        return BytecodeDecompilerOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status
        )
