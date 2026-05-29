"""Integration tests for the 5 adopted micro-agents cloned/adopted from external skills repos."""

from __future__ import annotations

import pytest

from pi_micro_agents import (
    AgentToolGuardInput,
    ConstantTimeInput,
    DimensionalAnalysisInput,
    HotPathAllocationInput,
    MemoryZeroizeInput,
    OrchestratorInput,
    PiAgentToolExecutionGuard,
    PiConstantTimeAuditor,
    PiDimensionalAnalysisSentry,
    PiHotPathAllocationAuditor,
    PiMemoryZeroizeSentry,
    PiOrchestrator,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean test environment variables before each test runs."""
    monkeypatch.delenv("PI_CONSTANT_TIME_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ZEROIZE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_DIMENSIONAL_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_AGENT_GUARD_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_PERF_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# 1. PiConstantTimeAuditor Verification
# =====================================================================
def test_constant_time_auditor_direct(monkeypatch):
    agent = PiConstantTimeAuditor()

    # Safe: no operations on secret
    code_safe = "int hash = key_len * 33;"
    res_safe = agent.audit_constant_time(
        ConstantTimeInput(file_path="crypto.py", source_code=code_safe, secrets_context=["secret_key"])
    )
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"
    assert res_safe.risk_score == 0.0

    # Vulnerable: division on secret
    code_vuln = "int val = secret_key / 2;"
    res_vuln = agent.audit_constant_time(
        ConstantTimeInput(file_path="crypto.py", source_code=code_vuln, secrets_context=["secret_key"])
    )
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_TIMING_RISK"
    assert res_vuln.risk_score == 95.0
    assert len(res_vuln.flagged_lines) > 0

    # Permissive Warn override
    monkeypatch.setenv("PI_CONSTANT_TIME_STRICT_MODE", "false")
    res_warn = agent.audit_constant_time(
        ConstantTimeInput(file_path="crypto.py", source_code=code_vuln, secrets_context=["secret_key"])
    )
    assert res_warn.is_secure
    assert res_warn.status == "WARN_TIMING_RISK"


# =====================================================================
# 2. PiMemoryZeroizeSentry Verification
# =====================================================================
def test_memory_zeroize_sentry_direct(monkeypatch):
    agent = PiMemoryZeroizeSentry()

    # Safe: uses secure wipe sodium_memzero
    code_safe = "sodium_memzero(password, 32);"
    res_safe = agent.audit_memory_zeroize(
        MemoryZeroizeInput(file_path="sec_buffer.c", source_code=code_safe, sensitive_symbols=["password"])
    )
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"

    # Vulnerable: uses standard memset which can be dead-store-eliminated
    code_vuln = "memset(password, 0, 32);"
    res_vuln = agent.audit_memory_zeroize(
        MemoryZeroizeInput(file_path="sec_buffer.c", source_code=code_vuln, sensitive_symbols=["password"])
    )
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_ZEROIZE_RISK"
    assert res_vuln.risk_score == 80.0

    # Permissive Warn override
    monkeypatch.setenv("PI_ZEROIZE_STRICT_MODE", "false")
    res_warn = agent.audit_memory_zeroize(
        MemoryZeroizeInput(file_path="sec_buffer.c", source_code=code_vuln, sensitive_symbols=["password"])
    )
    assert res_warn.is_secure
    assert res_warn.status == "WARN_ZEROIZE_RISK"


# =====================================================================
# 3. PiDimensionalAnalysisSentry Verification
# =====================================================================
def test_dimensional_analysis_sentry_direct(monkeypatch):
    agent = PiDimensionalAnalysisSentry()

    # Safe: unit matching
    code_safe = "uint256 total = balance_a + fee_a;"
    res_safe = agent.audit_dimensions(
        DimensionalAnalysisInput(
            file_path="finance.py", source_code=code_safe, unit_registry={"balance_a": "wei", "fee_a": "wei"}
        )
    )
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"

    # Vulnerable: mixed units without conversion
    code_vuln = "uint256 total = balance_a + rate_b;"
    res_vuln = agent.audit_dimensions(
        DimensionalAnalysisInput(
            file_path="finance.py", source_code=code_vuln, unit_registry={"balance_a": "wei", "rate_b": "gwei"}
        )
    )
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_DIMENSION_RISK"
    assert res_vuln.risk_score == 85.0

    # Permissive Warn override
    monkeypatch.setenv("PI_DIMENSIONAL_STRICT_MODE", "false")
    res_warn = agent.audit_dimensions(
        DimensionalAnalysisInput(
            file_path="finance.py", source_code=code_vuln, unit_registry={"balance_a": "wei", "rate_b": "gwei"}
        )
    )
    assert res_warn.is_secure
    assert res_warn.status == "WARN_DIMENSION_RISK"


# =====================================================================
# 4. PiAgentToolExecutionGuard Verification
# =====================================================================
def test_agent_tool_execution_guard_direct(monkeypatch):
    agent = PiAgentToolExecutionGuard()

    # Safe
    res_safe = agent.audit_agent_command(
        AgentToolGuardInput(
            command_string="pytest tests/integration/test_cloned_skills_agents.py", allowed_commands=["pytest", "git"]
        )
    )
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"

    # Vulnerable: highly destructive terminal pattern
    res_vuln = agent.audit_agent_command(
        AgentToolGuardInput(command_string="rm -rf /Users/clubpenguin/Downloads", allowed_commands=["rm", "pytest"])
    )
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_AGENT_RISK"
    assert res_vuln.risk_score == 100.0

    # Permissive Warn override
    monkeypatch.setenv("PI_AGENT_GUARD_STRICT_MODE", "false")
    res_warn = agent.audit_agent_command(
        AgentToolGuardInput(command_string="rm -rf /Users/clubpenguin/Downloads", allowed_commands=["rm", "pytest"])
    )
    assert res_warn.is_secure
    assert res_warn.status == "WARN_AGENT_RISK"


# =====================================================================
# 5. PiHotPathAllocationAuditor Verification
# =====================================================================
def test_hot_path_allocation_auditor_direct(monkeypatch):
    agent = PiHotPathAllocationAuditor()

    # Safe
    code_safe = "string.Compare(a, b, StringComparison.OrdinalIgnoreCase);"
    res_safe = agent.audit_hot_path(
        HotPathAllocationInput(file_path="program.cs", source_code=code_safe, hot_path_lines=[1])
    )
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"

    # Vulnerable: allocations inside hot-path lines
    code_vuln = 'if (name.ToLower() == "test")'
    res_vuln = agent.audit_hot_path(
        HotPathAllocationInput(file_path="program.cs", source_code=code_vuln, hot_path_lines=[1])
    )
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_PERF_RISK"
    assert res_vuln.risk_score == 75.0

    # Permissive Warn override
    monkeypatch.setenv("PI_PERF_STRICT_MODE", "false")
    res_warn = agent.audit_hot_path(
        HotPathAllocationInput(file_path="program.cs", source_code=code_vuln, hot_path_lines=[1])
    )
    assert res_warn.is_secure
    assert res_warn.status == "WARN_PERF_RISK"


# =====================================================================
# 6. PiOrchestrator End-to-End Routing Verification
# =====================================================================
def test_orchestrator_routing_constant_time(monkeypatch):
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")
    monkeypatch.setenv("PI_CONSTANT_TIME_STRICT_MODE", "true")
    orchestrator = PiOrchestrator()

    # Secure Case
    goal = "Please run a cryptographic constant-time timing side-channel audit on crypto.py"
    context = {"file_path": "crypto.py", "content": "int val = x * 2;", "secrets_context": ["secret_key"]}
    inp = OrchestratorInput(goal=goal, context=context)
    out = orchestrator.execute_goal(inp)
    assert out.success is True
    assert out.routed_agent == "PiConstantTimeAuditor"
    assert out.risk_score == 0.0

    # Vulnerable Case (rejection)
    context_vuln = {"file_path": "crypto.py", "content": "int val = secret_key % 2;", "secrets_context": ["secret_key"]}
    inp_vuln = OrchestratorInput(goal=goal, context=context_vuln)
    out_vuln = orchestrator.execute_goal(inp_vuln)
    assert out_vuln.success is False
    assert out_vuln.routed_agent == "PiConstantTimeAuditor"
    assert out_vuln.risk_score == 95.0


def test_orchestrator_routing_memory_zeroize(monkeypatch):
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ZEROIZE_STRICT_MODE", "true")
    orchestrator = PiOrchestrator()

    goal = "Run a secret wiping memory zeroize buffer scan on sec_buffer.c"
    context = {"file_path": "sec_buffer.c", "content": "memset(my_secret, 0, 32);", "sensitive_symbols": ["my_secret"]}
    inp = OrchestratorInput(goal=goal, context=context)
    out = orchestrator.execute_goal(inp)
    assert out.success is False
    assert out.routed_agent == "PiMemoryZeroizeSentry"
    assert out.risk_score == 80.0


def test_orchestrator_routing_dimensional_analysis(monkeypatch):
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")
    monkeypatch.setenv("PI_DIMENSIONAL_STRICT_MODE", "true")
    orchestrator = PiOrchestrator()

    goal = "Perform a unit mismatch sentry dimensional analysis on finance.py"
    context = {
        "file_path": "finance.py",
        "content": "uint256 total = a + b;",
        "unit_registry": {"a": "wei", "b": "gwei"},
    }
    inp = OrchestratorInput(goal=goal, context=context)
    out = orchestrator.execute_goal(inp)
    assert out.success is False
    assert out.routed_agent == "PiDimensionalAnalysisSentry"
    assert out.risk_score == 85.0


def test_orchestrator_routing_agent_tool_guard(monkeypatch):
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")
    monkeypatch.setenv("PI_AGENT_GUARD_STRICT_MODE", "true")
    orchestrator = PiOrchestrator()

    goal = "Check safety using agent tool guard"
    context = {"command_string": "rm -rf /Users/clubpenguin/Downloads", "allowed_commands": ["rm"]}
    inp = OrchestratorInput(goal=goal, context=context)
    out = orchestrator.execute_goal(inp)
    assert out.success is False
    assert out.routed_agent == "PiAgentToolExecutionGuard"
    assert out.risk_score == 100.0


def test_orchestrator_routing_hot_path_allocation(monkeypatch):
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")
    monkeypatch.setenv("PI_PERF_STRICT_MODE", "true")
    orchestrator = PiOrchestrator()

    goal = "Run hot-path allocation diagnostic performance auditor check on program.cs"
    context = {"file_path": "program.cs", "content": 'if (line.ToLower() == "test")', "hot_path_lines": [1]}
    inp = OrchestratorInput(goal=goal, context=context)
    out = orchestrator.execute_goal(inp)
    assert out.success is False
    assert out.routed_agent == "PiHotPathAllocationAuditor"
    assert out.risk_score == 75.0
