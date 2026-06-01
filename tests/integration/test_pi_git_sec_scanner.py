"""Integration tests for the PiGitSecScanner micro-agent."""

from __future__ import annotations

import pytest

from pi_micro_agents.pi_git_sec_scanner import (
    GitSecInput,
    PiGitSecScanner,
    is_strict_mode,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_GIT_SEC_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Clean files scanning (no risks)
# =====================================================================
def test_clean_files():
    """Verify that clean codebase files and dependencies produce zero risk scores and pass successfully."""
    scanner = PiGitSecScanner()

    # Clean requirements.txt with pinned dependencies
    clean_reqs = "requests==2.31.0\npytest===7.4.3\npydantic==2.5.2"
    inp_reqs = GitSecInput(filename="requirements.txt", content=clean_reqs)
    out_reqs = scanner.scan_file(inp_reqs)

    assert out_reqs.is_secure is True
    assert out_reqs.risk_score == 0.0
    assert out_reqs.status == "PASSED"
    assert len(out_reqs.flagged_vulnerabilities) == 0

    # Clean python source file
    clean_py = """
def hello_world():
    print("Hello from PI-Platform")
"""
    inp_py = GitSecInput(filename="main.py", content=clean_py)
    out_py = scanner.scan_file(inp_py)

    assert out_py.is_secure is True
    assert out_py.risk_score == 0.0
    assert out_py.status == "PASSED"


# =====================================================================
# Test 2: Unpinned / Range dependencies in requirements.txt
# =====================================================================
def test_unpinned_dependencies_requirements():
    """Verify that unpinned or range dependencies in requirements.txt trigger risk flags."""
    scanner = PiGitSecScanner()

    reqs_with_unpinned = "requests>=2.0.0\nflask\npydantic==2.5.2"
    inp = GitSecInput(filename="requirements.txt", content=reqs_with_unpinned)
    out = scanner.scan_file(inp)

    # Risk score for unpinned dependencies is 75.0, so it will flag WARN_VULNERABILITY but remain secure under normal mode
    assert out.is_secure is True
    assert out.risk_score == 75.0
    assert out.status == "WARN_VULNERABILITY"
    assert any("unpinned or range dependency" in viol for viol in out.flagged_vulnerabilities)


# =====================================================================
# Test 3: Unpinned / Floating dependencies in package.json
# =====================================================================
def test_unpinned_dependencies_package_json():
    """Verify that wildcard or floating/range dependencies in package.json trigger risk flags."""
    scanner = PiGitSecScanner()

    pkg_json = """
    {
      "name": "pi-ui",
      "dependencies": {
        "react": "^18.2.0",
        "lodash": "*"
      }
    }
    """
    inp = GitSecInput(filename="package.json", content=pkg_json)
    out = scanner.scan_file(inp)

    assert out.is_secure is True
    assert out.risk_score == 75.0
    assert out.status == "WARN_VULNERABILITY"
    assert len(out.flagged_vulnerabilities) == 2
    assert any("react" in viol for viol in out.flagged_vulnerabilities)
    assert any("lodash" in viol for viol in out.flagged_vulnerabilities)


# =====================================================================
# Test 4: Suspicious/Typosquatted packages
# =====================================================================
def test_suspicious_packages():
    """Verify that typosquatted or high-risk package names in dependency files are flagged."""
    scanner = PiGitSecScanner()

    bad_reqs = "requests==2.31.0\ndiscord-py-self==1.0.0"
    inp = GitSecInput(filename="requirements.txt", content=bad_reqs)
    out = scanner.scan_file(inp)

    # Suspicious packages represent 85.0 risk score, which triggers REJECTED_VULNERABILITY in strict-mode
    assert out.risk_score == 85.0
    assert any("high-risk typosquatted / suspicious package" in viol for viol in out.flagged_vulnerabilities)


# =====================================================================
# Test 5: Dangerous Code execution patterns
# =====================================================================
def test_dangerous_executions():
    """Verify that dangerous functions like eval, exec, and subprocess shell=True are flagged."""
    scanner = PiGitSecScanner()

    # Target containing eval and subprocess
    unsafe_py = """
def run_command(cmd):
    eval(cmd)
    import subprocess
    subprocess.Popen(cmd, shell=True)
"""
    inp = GitSecInput(filename="helper.py", content=unsafe_py)
    out = scanner.scan_file(inp)

    assert out.risk_score == 90.0
    assert len(out.flagged_vulnerabilities) == 2
    assert any("eval()" in viol for viol in out.flagged_vulnerabilities)
    assert any("subprocess with shell=True" in viol for viol in out.flagged_vulnerabilities)


# =====================================================================
# Test 6: Hardcoded Secret detection
# =====================================================================
def test_hardcoded_secrets():
    """Verify that hardcoded client secrets, private keys, and API keys are flagged."""
    scanner = PiGitSecScanner()

    # Target containing hardcoded api key
    leaky_py = """
API_KEY = "sk-proj-1234567890abcdef1234567890abcdef"
PRIVATE_KEY = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef"
"""
    inp = GitSecInput(filename="config.py", content=leaky_py)
    out = scanner.scan_file(inp)

    assert out.risk_score == 95.0
    assert len(out.flagged_vulnerabilities) == 2
    assert any("hardcoded API key" in viol for viol in out.flagged_vulnerabilities)
    assert any("hardcoded private key" in viol for viol in out.flagged_vulnerabilities)


# =====================================================================
# Test 7: Strict Mode Enforcement Gating
# =====================================================================
def test_strict_mode_enforcement(monkeypatch):
    """Verify that strict mode blocks execution on high-risk files but warning-only passes them."""
    scanner = PiGitSecScanner()
    leaky_py = 'API_KEY = "sk-proj-1234567890abcdef1234567890abcdef"'
    inp = GitSecInput(filename="config.py", content=leaky_py)

    # 1. Enforce STRICT MODE (default / explicitly set)
    monkeypatch.setenv("PI_GIT_SEC_STRICT_MODE", "true")
    assert is_strict_mode() is True
    out_strict = scanner.scan_file(inp)
    assert out_strict.is_secure is False
    assert out_strict.status == "REJECTED_VULNERABILITY"

    # 2. WARNING-ONLY MODE (disabled strict mode)
    monkeypatch.setenv("PI_GIT_SEC_STRICT_MODE", "false")
    assert is_strict_mode() is False
    out_warn = scanner.scan_file(inp)
    assert out_warn.is_secure is True
    assert out_warn.status == "WARN_VULNERABILITY"
