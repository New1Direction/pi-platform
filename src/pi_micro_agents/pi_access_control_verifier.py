from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Strict-mode configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_ACCESS_CONTROL_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_ACCESS_CONTROL_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Pydantic-Enforced Input/Output Envelopes
class AccessControlInput(BaseModel):
    file_path: str = Field(..., description="Solidity source file path")
    solidity_code: str = Field(..., description="Solidity source code content")
    check_level: str = Field(default="STRICT", description="Strictness level of parsing: STRICT, MEDIUM")
    allowed_modifiers: List[str] = Field(
        default_factory=list, description="User-defined custom access control modifiers"
    )


class AccessControlOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if contract is free from access control vulnerabilities")
    vulnerable_functions: List[str] = Field(default_factory=list, description="Vulnerable function names")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed line and violation findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification (PASSED, WARN_ACCESS_CONTROL, REJECTED_ACCESS_CONTROL)")


# 3. Helper function to extract concrete Solidity functions
def extract_solidity_functions(solidity_code: str) -> List[Tuple[str, str, int]]:
    functions = []
    code_len = len(solidity_code)

    # Pattern matching "function [name] (" or "constructor ("
    pattern = re.compile(r"\b(function|constructor)\b\s*([a-zA-Z0-9_]*)\s*\(")

    for match in pattern.finditer(solidity_code):
        keyword = match.group(1)
        name = match.group(2)
        func_name = name if keyword == "function" else "constructor"

        start_idx = match.start()

        # Calculate line number of start_idx
        start_line = solidity_code[:start_idx].count("\n") + 1

        # Semicolons and opening braces determine concrete vs abstract functions
        semicolon_idx = solidity_code.find(";", start_idx)
        brace_idx = solidity_code.find("{", start_idx)

        if brace_idx == -1 or (semicolon_idx != -1 and semicolon_idx < brace_idx):
            continue

        # Match braces to find full function block body
        brace_count = 1
        curr_idx = brace_idx + 1
        while curr_idx < code_len and brace_count > 0:
            char = solidity_code[curr_idx]
            if char == "{":
                brace_count += 1
            elif char == "}":
                brace_count -= 1
            curr_idx += 1

        if brace_count == 0:
            func_body = solidity_code[start_idx:curr_idx]
            functions.append((func_name, func_body, start_line))

    return functions


# 4. Core Micro-Agent Class
class PiAccessControlVerifier:
    """Specialized Web3 micro-agent that audits Solidity contracts for missing modifiers and privilege elevations."""

    def __init__(self) -> None:
        self.agent_name = "PiAccessControlVerifier"

    def audit_access_control(self, input_envelope: AccessControlInput) -> AccessControlOutput:
        """Autonomously scans Solidity functions for missing access control modifiers and uninitialized owner configurations."""
        code = input_envelope.solidity_code
        functions = extract_solidity_functions(code)

        vulnerable_funcs = []
        flagged_findings = []

        # List of sensitive admin action keywords in function names
        sensitive_keywords = [
            "mint",
            "burn",
            "withdraw",
            "transferownership",
            "setowner",
            "pause",
            "unpause",
            "upgrade",
            "selfdestruct",
            "kill",
            "setrole",
            "grantrole",
            "initialize",
        ]

        # Base list of standard access control modifiers
        standard_modifiers = [
            "onlyowner",
            "onlyadmin",
            "hasrole",
            "onlyrole",
            "requiresauth",
            "onlygovernor",
            "onlyminter",
        ]

        # Include user custom modifiers
        for m in input_envelope.allowed_modifiers:
            standard_modifiers.append(m.lower())

        # Check if ownership variable is defined in contract but constructor/initializer is missing entirely
        has_owner_var = "address" in code and "owner" in code
        has_initializer_mechanism = False

        for func_name, func_body, start_line in functions:
            if func_name in ["constructor", "initialize"]:
                has_initializer_mechanism = True

            # Clean body of comments to prevent false positives
            cleaned_body = re.sub(r"//.*", "", func_body)
            cleaned_body = re.sub(r"/\*.*?\*/", "", cleaned_body, flags=re.DOTALL)

            # Identify internal/private vs public/external
            # If function signature does not declare private/internal, it defaults/explicitly defines public/external
            # We can inspect the function declaration line (up to first {)
            declaration_part = func_body.split("{")[0].lower()

            is_internal_or_private = "internal" in declaration_part or "private" in declaration_part

            # Check if this is a sensitive function
            is_sensitive = any(kw in func_name.lower() for kw in sensitive_keywords)

            # Also check if it does privileged state modifications inside, like upgrading ownership/roles
            has_privilege_elevation = False
            elevation_trigger = ""
            if not is_internal_or_private and func_name != "constructor":
                # Scans for state assignment changes to owner, admin, or roles
                lines = cleaned_body.splitlines()
                for offset, line in enumerate(lines):
                    line_num = start_line + offset
                    stripped = line.strip()
                    # Look for assignments to admin variables or role mappings
                    if "=" in stripped and not any(comp in stripped for comp in ["==", "<=", ">=", "!="]):
                        # Match variables: owner, admin, roles, _owner, role
                        if any(
                            term in stripped.lower()
                            for term in ["owner =", "admin =", "roles[", "isadmin[", "hasrole["]
                        ):
                            # Exclude local variable definitions
                            if not any(stripped.startswith(t) for t in ["uint", "address ", "bool ", "bytes "]):
                                has_privilege_elevation = True
                                elevation_trigger = f"State assignment '{stripped}' on Line {line_num}"
                                break

            if (is_sensitive or has_privilege_elevation) and not is_internal_or_private:
                # Constructors do not need modifiers, and initialize might have special rules
                if func_name == "constructor":
                    continue

                # Scans declaration header for standard or user modifiers
                has_modifier = False
                for modifier in standard_modifiers:
                    # Match modifier name as a whole word or followed by brackets e.g. onlyOwner, hasRole(...)
                    pattern = re.compile(rf"\b{modifier}\b")
                    if pattern.search(declaration_part):
                        has_modifier = True
                        break

                if not has_modifier:
                    if func_name not in vulnerable_funcs:
                        vulnerable_funcs.append(func_name)

                    reason = ""
                    if is_sensitive:
                        reason = f"Sensitive administrative function '{func_name}' is declared public/external but lacks an access control modifier."
                    elif has_privilege_elevation:
                        reason = f"Function '{func_name}' performs sensitive privilege modification ({elevation_trigger}) but is public/external and lacks an access control modifier."

                    flagged_findings.append(reason)

        # Check for uninitialized ownership
        if has_owner_var and not has_initializer_mechanism:
            flagged_findings.append(
                "Contract defines an 'owner' variable but lacks a constructor or initializer function to configure ownership."
            )
            vulnerable_funcs.append("contract_structure")

        is_secure = len(vulnerable_funcs) == 0
        risk_score = 95.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_ACCESS_CONTROL"
            else:
                status = "WARN_ACCESS_CONTROL"
                is_secure = True  # Warn only in non-strict mode

        return AccessControlOutput(
            is_secure=is_secure,
            vulnerable_functions=vulnerable_funcs,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
