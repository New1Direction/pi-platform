"""The orchestrator AST-safety shield must not treat non-Python scanner INPUT as
a security violation. The content fed to a scanner is data (Solidity, Docker,
SQL, prose), never a Python payload we execute — so a SyntaxError is the normal
case, not a block. Genuine dangerous constructs in real Python are still flagged.
"""

from __future__ import annotations

import pytest

from pi_micro_agents.orchestrator.shield import PiOrchestratorShield as Shield


@pytest.mark.parametrize(
    "content",
    [
        "pragma solidity ^0.8.0;\ncontract B { function w() public {} }",
        "FROM ubuntu:latest\nRUN apt-get update",
        "SELECT * FROM users WHERE name = '' OR 1=1",
        "just some prose — not code at all",
        "",
    ],
)
def test_non_python_scan_input_is_not_a_violation(content):
    # Previously these tripped "Syntax error in proposed Python payload" and blocked
    # the agent (diverted to PIGovernShield). Now: no violation.
    assert Shield.check_ast_safety({"content": content}) is None


@pytest.mark.parametrize(
    "content",
    [
        "eval(user_input)",
        "import os\nos.system('rm -rf /')",
        "from subprocess import run\nrun('x', shell=True)",
    ],
)
def test_real_dangerous_python_still_flagged(content):
    violations = Shield.check_ast_safety({"content": content})
    assert violations, f"expected a violation for: {content!r}"
    assert all("syntax error" not in v.lower() for v in violations)
