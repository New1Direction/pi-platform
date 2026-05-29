"""Integration tests for the PiPromptLeakBuster micro-agent."""

from __future__ import annotations

import os
import pytest

from pi_micro_agents.pi_prompt_leak_buster import (
    PiPromptLeakBuster,
    LeakBusterInput,
    LeakBusterOutput,
    detect_leak_anomalies,
    is_strict_mode,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_LEAK_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Clean outgoing content (no leaks)
# =====================================================================
def test_clean_content():
    """Verify that clean outgoing text produces zero risk scores and passes successfully."""
    buster = PiPromptLeakBuster()

    clean_text = "Here is the summary of this week's AI trends: CUDA optimization and agent-orchestration frameworks."
    inp = LeakBusterInput(text=clean_text)
    out = buster.scan_text(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert len(out.flagged_leaks) == 0


# =====================================================================
# Test 2: Credential & Private Key leaks
# =====================================================================
def test_credential_leaks():
    """Verify that accidental leaks of private keys and API keys are flagged."""
    buster = PiPromptLeakBuster()

    leaky_text = (
        "Draft post: Just resolved the deployment bug! Our main endpoint config: "
        "api_key = 'sk-proj-1234567890abcdef1234567890abcdef'. Happy coding!"
    )
    inp = LeakBusterInput(text=leaky_text)
    out = buster.scan_text(inp)

    assert out.risk_score == 95.0
    assert any("potential leak of secret information" in leak for leak in out.flagged_leaks)


# =====================================================================
# Test 3: Personally Identifiable Information (PII) leaks
# =====================================================================
def test_pii_leaks():
    """Verify that email addresses and phone numbers are flagged as PII leaks."""
    buster = PiPromptLeakBuster()

    # 1. Email leak
    email_text = "Please reach out to clubpenguin@piplatform.io for support."
    inp_email = LeakBusterInput(text=email_text)
    out_email = buster.scan_text(inp_email)

    assert out_email.risk_score == 80.0
    assert any("PII" in leak and "email" in leak for leak in out_email.flagged_leaks)

    # 2. Phone leak
    phone_text = "You can dial our support hotlines: +1 (555) 019-2834 or 555-019-2834."
    inp_phone = LeakBusterInput(text=phone_text)
    out_phone = buster.scan_text(inp_phone)

    assert out_phone.risk_score == 80.0
    assert any("PII" in leak and "phone" in leak for leak in out_phone.flagged_leaks)


# =====================================================================
# Test 4: System Prompt / Instruction leakage
# =====================================================================
def test_system_prompt_leaks():
    """Verify that outgoing text containing system instructions or prompt overrides is flagged."""
    buster = PiPromptLeakBuster()

    leaky_text = (
        "Here is what happened: the user input was 'You are a helpful assistant designed by DeepMind'. "
        "This triggered a system override instruction."
    )
    inp = LeakBusterInput(text=leaky_text)
    out = buster.scan_text(inp)

    assert out.risk_score == 85.0
    assert len(out.flagged_leaks) == 1
    assert any("system prompt role instruction leakage" in leak for leak in out.flagged_leaks)


# =====================================================================
# Test 5: Strict Mode Gating Enforcement
# =====================================================================
def test_strict_mode_gating(monkeypatch):
    """Verify that strict mode blocks execution on flagged leaks, but warning-only passes them."""
    buster = PiPromptLeakBuster()
    leaky_text = "Warning: email leak detected at agent1@piplatform.io"
    inp = LeakBusterInput(text=leaky_text)

    # 1. Enforce STRICT MODE (default / explicitly set)
    monkeypatch.setenv("PI_LEAK_STRICT_MODE", "true")
    assert is_strict_mode() is True
    out_strict = buster.scan_text(inp)
    assert out_strict.is_secure is False
    assert out_strict.status == "REJECTED_LEAK"

    # 2. WARNING-ONLY MODE (disabled strict mode)
    monkeypatch.setenv("PI_LEAK_STRICT_MODE", "false")
    assert is_strict_mode() is False
    out_warn = buster.scan_text(inp)
    assert out_warn.is_secure is True
    assert out_warn.status == "WARN_LEAK"
