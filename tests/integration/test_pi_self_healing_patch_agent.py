"""Integration tests for the PiSelfHealingPatchAgent micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import pytest

from pi_micro_agents.pi_orchestrator import OrchestratorInput, PiOrchestrator
from pi_micro_agents.pi_self_healing_patch_agent import (
    PiSelfHealingPatchAgent,
    SelfHealingInput,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_PATCH_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Dependency Pinning (UNPINNED_DEP) for requirements.txt style
# =====================================================================
def test_self_healing_requirements_pinning():
    """Verify that unpinned packages in requirements.txt are correctly pinned to stable safe versions."""
    agent = PiSelfHealingPatchAgent()

    source = "flask\nrequests>=2.0.0\npytest\nnumpy\n"
    inp = SelfHealingInput(
        file_path="requirements.txt", source_code=source, vulnerability_type="UNPINNED_DEP", vulnerable_lines=[1, 2, 3]
    )

    out = agent.heal_vulnerabilities(inp)

    assert out.patch_synthesized is True
    assert out.status == "PASSED"
    assert out.patch_safety_score == 100.0

    lines = out.patched_code.splitlines()
    assert lines[0] == "flask==3.0.0"
    assert lines[1] == "requests==2.31.0"
    assert lines[2] == "pytest==7.4.3"
    assert lines[3] == "numpy"  # Not in vulnerable_lines, must remain unpatched

    assert any("Pinned package 'flask'" in r for r in out.remediations)
    assert any("Pinned package 'requests'" in r for r in out.remediations)
    assert any("Pinned package 'pytest'" in r for r in out.remediations)


# =====================================================================
# Test 2: Dependency Pinning (UNPINNED_DEP) for package.json style
# =====================================================================
def test_self_healing_package_json_pinning():
    """Verify that unpinned dependency keys in package.json are correctly pinned."""
    agent = PiSelfHealingPatchAgent()

    source = '{\n  "dependencies": {\n    "react": "^18.2.0",\n    "lodash": "*",\n    "other": "1.0.0"\n  }\n}\n'
    # Target "react" and "lodash" on lines 3 and 4
    inp = SelfHealingInput(
        file_path="package.json", source_code=source, vulnerability_type="UNPINNED_DEP", vulnerable_lines=[3, 4]
    )

    out = agent.heal_vulnerabilities(inp)

    assert out.patch_synthesized is True
    assert out.status == "PASSED"

    lines = out.patched_code.splitlines()
    assert '"react": "18.2.0",' in lines[2]
    assert '"lodash": "4.17.21",' in lines[3]
    assert '"other": "1.0.0"' in lines[4]  # Unmodified line

    assert any("Pinned JSON package 'react'" in r for r in out.remediations)
    assert any("Pinned JSON package 'lodash'" in r for r in out.remediations)


# =====================================================================
# Test 3: Dangerous Eval Blocking (DANGEROUS_EVAL)
# =====================================================================
def test_self_healing_eval_blocking():
    """Verify that dangerous eval calls are safely commented out and replaced."""
    agent = PiSelfHealingPatchAgent()

    source = "def compute_dynamic(expr):\n    return eval(expr)\ndef safe_func():\n    return 42\n"
    inp = SelfHealingInput(
        file_path="math_utils.py", source_code=source, vulnerability_type="DANGEROUS_EVAL", vulnerable_lines=[2]
    )

    out = agent.heal_vulnerabilities(inp)

    assert out.patch_synthesized is True
    assert out.status == "PASSED"
    assert out.patch_safety_score == 100.0

    # Ensure python syntax compiles successfully after replacement
    try:
        compile(out.patched_code, "test_patched.py", "exec")
    except SyntaxError as e:
        pytest.fail(f"Patched code failed syntax compilation: {e}")

    lines = out.patched_code.splitlines()
    assert "# TODO (Security Remediation): Blocked dangerous eval statement" in lines[1]
    assert "pass" in lines[2]
    assert "def safe_func():" in lines[3]


# =====================================================================
# Test 4: Strict Mode Toggle & Safety Scores
# =====================================================================
def test_self_healing_strict_mode_toggle(monkeypatch):
    """Verify that strict mode correctly filters patches with low safety scores."""
    agent = PiSelfHealingPatchAgent()

    # Source code with no actual matches for pinning or eval on vulnerable lines
    source = "some_random_code_without_vulns = 1\n"
    inp = SelfHealingInput(
        file_path="main.py", source_code=source, vulnerability_type="DANGEROUS_EVAL", vulnerable_lines=[1]
    )

    # 1. Default/Strict Mode: Safety score of 50.0 (unapplied) triggers REJECTED_PATCH status
    monkeypatch.setenv("PI_PATCH_STRICT_MODE", "true")
    out_strict = agent.heal_vulnerabilities(inp)
    assert out_strict.patch_synthesized is False
    assert out_strict.status == "REJECTED_PATCH"
    assert out_strict.patch_safety_score == 50.0

    # 2. Non-Strict Mode: Safety score of 50.0 triggers WARN_PATCH status
    monkeypatch.setenv("PI_PATCH_STRICT_MODE", "false")
    out_warn = agent.heal_vulnerabilities(inp)
    assert out_warn.patch_synthesized is False
    assert out_warn.status == "WARN_PATCH"
    assert out_warn.patch_safety_score == 50.0


# =====================================================================
# Test 5: Dynamic Orchestrator Routing (Success Consensus)
# =====================================================================
def test_orchestrator_routing_to_self_healing(monkeypatch):
    """Verify that PiOrchestrator correctly identifies self-healing goals and executes consensus."""
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")
    orchestrator = PiOrchestrator()

    source = "flask\nrequests>=2.0.0"
    goal = "Self heal vulnerability in requirements.txt"
    inp = OrchestratorInput(
        goal=goal,
        context={
            "file_path": "requirements.txt",
            "source_code": source,
            "vulnerability_type": "UNPINNED_DEP",
            "vulnerable_lines": [1, 2],
        },
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is True
    assert res.routed_agent == "PiSelfHealingPatchAgent"
    assert res.risk_score == 0.0
    assert "consensus_telemetry" in res.result_details
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"

    patched_code = res.result_details["patched_code"]
    assert "flask==3.0.0" in patched_code
    assert "requests==2.31.0" in patched_code


# =====================================================================
# Test 6: Orchestrator Consensus Divergence Alarm (Fail-Shut)
# =====================================================================
def test_orchestrator_consensus_divergence_alarm(monkeypatch):
    """Verify that inconsistent consensus mock outputs trigger a fail-shut block in the orchestrator."""
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    # Mock evaluate_consensus to return a broken report
    from pi_semantic_radius.consensus_breaker import DivergenceReport, PiConsensusBreaker

    def mock_evaluate_consensus(self, prompt, responses):
        return DivergenceReport(
            prompt=prompt,
            responses=responses,
            semantic_divergence=85.0,
            structural_divergence=0.0,
            consensus_divergence_score=85.0,
            is_broken=True,
        )

    monkeypatch.setattr(PiConsensusBreaker, "evaluate_consensus", mock_evaluate_consensus)

    orchestrator = PiOrchestrator()
    goal = "Perform safe patch on math_utils.py code repair"

    # 3 mock runs with split verdicts or high content divergence
    # Run 1 & 2 agree on patch_synthesized=True and patched_code, but Run 3 disagrees or has different schema keys/values
    mock_runs = [
        {
            "patch_synthesized": True,
            "patched_code": "# TODO\npass",
            "patch_diff": "- eval\n+ # TODO\n+ pass",
            "patch_safety_score": 100.0,
            "remediations": ["Replaced eval"],
            "status": "PASSED",
        },
        {
            "patch_synthesized": True,
            "patched_code": "# TODO\npass",
            "patch_diff": "- eval\n+ # TODO\n+ pass",
            "patch_safety_score": 100.0,
            "remediations": ["Replaced eval"],
            "status": "PASSED",
        },
        {
            "patch_synthesized": False,
            "patched_code": "eval()",
            "patch_diff": "",
            "patch_safety_score": 50.0,
            "remediations": [],
            "status": "REJECTED_PATCH",
        },
    ]

    inp = OrchestratorInput(
        goal=goal,
        context={
            "file_path": "math_utils.py",
            "source_code": "eval()",
            "vulnerability_type": "DANGEROUS_EVAL",
            "vulnerable_lines": [1],
            "mock_consensus_runs": mock_runs,
        },
    )

    res = orchestrator.execute_goal(inp)

    # In strict mode, high divergence (or a split vote) triggers fail-shut success=False
    assert res.success is False
    assert res.routed_agent == "PiSelfHealingPatchAgent"
    assert "consensus_telemetry" in res.result_details
    assert res.result_details["consensus_telemetry"]["status"] == "REJECTED_DIVERGENCE_ALARM"
    assert res.result_details["consensus_telemetry"]["divergence_score"] >= 60.0
