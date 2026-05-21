"""Integration tests for the 10 additional highly specialized dual-use PI micro-agents (Cohort 8: Agents 81-90)."""

from __future__ import annotations

import os
import pytest

from pi_micro_agents import (
    PiRustSolanaBorshSerializationLeak,
    SolanaBorshLeakInput,
    PiRustSolanaReentrancyCrossProgramSentry,
    SolanaReentrancyCrossInput,
    PiRustSolanaSysvarClockVerification,
    SolanaSysvarClockInput,
    PiZKSignalUnconstrainedConstraint,
    ZKSignalUnconstrainedInput,
    PiZKDivByZeroConstraintAuditor,
    ZKDivByZeroConstraintInput,
    PiZKSignalShadowingSignalSentry,
    ZKSignalShadowingInput,
    PiZKPublicInputLeakageAuditor,
    ZKPublicInputLeakageInput,
    PiZKNonPrimeFieldRangeSentry,
    ZKNonPrimeFieldRangeInput,
    PiZKUnusedConstraintVariables,
    ZKUnusedConstraintInput,
    PiZKProofForgingValidationSentry,
    ZKProofForgingValidationInput,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean test environment variables before each test runs."""
    monkeypatch.delenv("PI_SOLANA_BORSH_LEAK_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_SOLANA_REENTRANCY_CROSS_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_SOLANA_SYSVAR_CLOCK_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ZK_SIGNAL_UNCONSTRAINED_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ZK_DIV_BY_ZERO_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ZK_SIGNAL_SHADOWING_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ZK_PUBLIC_INPUT_LEAKAGE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ZK_NON_PRIME_FIELD_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ZK_UNUSED_CONSTRAINT_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ZK_PROOF_FORGING_STRICT_MODE", raising=False)


# =====================================================================
# 81. PiRustSolanaBorshSerializationLeak Verification
# =====================================================================
def test_rust_solana_borsh_serialization_leak(monkeypatch):
    agent = PiRustSolanaBorshSerializationLeak()

    code_vuln = """
    #[derive(BorshSerialize)]
    pub struct DynamicData {
        pub items: Vec<u8>,
    }
    """
    res_vuln = agent.audit_borsh_leak(SolanaBorshLeakInput(file_path="lib.rs", rust_code=code_vuln))
    assert not res_vuln.is_secure
    assert "DynamicData" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_SOLANA_BORSH_LEAK"

    monkeypatch.setenv("PI_SOLANA_BORSH_LEAK_STRICT_MODE", "false")
    res_warn = agent.audit_borsh_leak(SolanaBorshLeakInput(file_path="lib.rs", rust_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_SOLANA_BORSH_LEAK"

    code_safe = """
    #[derive(BorshSerialize)]
    pub struct SafeData {
        pub items: [u8; 32],
    }
    """
    res_safe = agent.audit_borsh_leak(SolanaBorshLeakInput(file_path="lib.rs", rust_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 82. PiRustSolanaReentrancyCrossProgramSentry Verification
# =====================================================================
def test_rust_solana_reentrancy_cross_program_sentry(monkeypatch):
    agent = PiRustSolanaReentrancyCrossProgramSentry()

    code_vuln = """
    pub fn process_tx() {
        invoke(&ix, accounts)?;
        let val = 100;
    }
    """
    res_vuln = agent.audit_reentrancy_cross(SolanaReentrancyCrossInput(file_path="lib.rs", rust_code=code_vuln))
    assert not res_vuln.is_secure
    assert "process_tx" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_SOLANA_REENTRANCY_CROSS"

    monkeypatch.setenv("PI_SOLANA_REENTRANCY_CROSS_STRICT_MODE", "false")
    res_warn = agent.audit_reentrancy_cross(SolanaReentrancyCrossInput(file_path="lib.rs", rust_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_SOLANA_REENTRANCY_CROSS"

    code_safe = """
    pub fn process_tx() {
        let val = 100;
        invoke(&ix, accounts)?;
    }
    """
    res_safe = agent.audit_reentrancy_cross(SolanaReentrancyCrossInput(file_path="lib.rs", rust_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 83. PiRustSolanaSysvarClockVerification Verification
# =====================================================================
def test_rust_solana_sysvar_clock_verification(monkeypatch):
    agent = PiRustSolanaSysvarClockVerification()

    code_vuln = """
    pub fn get_time() {
        let now = Clock::get()?.unix_timestamp;
    }
    """
    res_vuln = agent.audit_sysvar_clock(SolanaSysvarClockInput(file_path="lib.rs", rust_code=code_vuln))
    assert not res_vuln.is_secure
    assert "Line 3" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_SOLANA_SYSVAR_CLOCK"

    monkeypatch.setenv("PI_SOLANA_SYSVAR_CLOCK_STRICT_MODE", "false")
    res_warn = agent.audit_sysvar_clock(SolanaSysvarClockInput(file_path="lib.rs", rust_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_SOLANA_SYSVAR_CLOCK"

    code_safe = """
    pub fn get_time() {
        let now = 123456789;
    }
    """
    res_safe = agent.audit_sysvar_clock(SolanaSysvarClockInput(file_path="lib.rs", rust_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 84. PiZKSignalUnconstrainedConstraint Verification
# =====================================================================
def test_zk_signal_unconstrained_constraint(monkeypatch):
    agent = PiZKSignalUnconstrainedConstraint()

    code_vuln = """
    template Unsafe() {
        signal input in;
        signal output out;
        out <-- in * 2;
    }
    """
    res_vuln = agent.audit_unconstrained_signals(ZKSignalUnconstrainedInput(file_path="circuit.circom", circom_code=code_vuln))
    assert not res_vuln.is_secure
    assert "out" in res_vuln.vulnerable_signals
    assert res_vuln.status == "REJECTED_ZK_SIGNAL_UNCONSTRAINED"

    monkeypatch.setenv("PI_ZK_SIGNAL_UNCONSTRAINED_STRICT_MODE", "false")
    res_warn = agent.audit_unconstrained_signals(ZKSignalUnconstrainedInput(file_path="circuit.circom", circom_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_ZK_SIGNAL_UNCONSTRAINED"

    code_safe = """
    template Safe() {
        signal input in;
        signal output out;
        out === in * 2;
    }
    """
    res_safe = agent.audit_unconstrained_signals(ZKSignalUnconstrainedInput(file_path="circuit.circom", circom_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 85. PiZKDivByZeroConstraintAuditor Verification
# =====================================================================
def test_zk_div_by_zero_constraint_auditor(monkeypatch):
    agent = PiZKDivByZeroConstraintAuditor()

    code_vuln = """
    template DivZero() {
        signal input a;
        signal input b;
        signal output out;
        out <-- a / b;
    }
    """
    res_vuln = agent.audit_div_by_zero(ZKDivByZeroConstraintInput(file_path="circuit.circom", circom_code=code_vuln))
    assert not res_vuln.is_secure
    assert "b" in res_vuln.vulnerable_signals
    assert res_vuln.status == "REJECTED_ZK_DIV_BY_ZERO"

    monkeypatch.setenv("PI_ZK_DIV_BY_ZERO_STRICT_MODE", "false")
    res_warn = agent.audit_div_by_zero(ZKDivByZeroConstraintInput(file_path="circuit.circom", circom_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_ZK_DIV_BY_ZERO"

    code_safe = """
    template Safe() {
        signal input a;
        signal input b;
        signal output out;
        assert(b != 0);
        out <-- a / b;
    }
    """
    res_safe = agent.audit_div_by_zero(ZKDivByZeroConstraintInput(file_path="circuit.circom", circom_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 86. PiZKSignalShadowingSignalSentry Verification
# =====================================================================
def test_zk_signal_shadowing_signal_sentry(monkeypatch):
    agent = PiZKSignalShadowingSignalSentry()

    code_vuln = """
    template Shadow() {
        signal input x;
        signal input x;
    }
    """
    res_vuln = agent.audit_signal_shadowing(ZKSignalShadowingInput(file_path="circuit.circom", circom_code=code_vuln))
    assert not res_vuln.is_secure
    assert "x" in res_vuln.vulnerable_signals
    assert res_vuln.status == "REJECTED_ZK_SIGNAL_SHADOWING"

    monkeypatch.setenv("PI_ZK_SIGNAL_SHADOWING_STRICT_MODE", "false")
    res_warn = agent.audit_signal_shadowing(ZKSignalShadowingInput(file_path="circuit.circom", circom_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_ZK_SIGNAL_SHADOWING"

    code_safe = """
    template Safe() {
        signal input x;
        signal input y;
    }
    """
    res_safe = agent.audit_signal_shadowing(ZKSignalShadowingInput(file_path="circuit.circom", circom_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 87. PiZKPublicInputLeakageAuditor Verification
# =====================================================================
def test_zk_public_input_leakage_auditor(monkeypatch):
    agent = PiZKPublicInputLeakageAuditor()

    code_vuln = """
    template Leak() {
        signal input public_val;
        signal input secret_val;
        public_val <-- secret_val;
    }
    """
    res_vuln = agent.audit_public_input_leakage(ZKPublicInputLeakageInput(file_path="circuit.circom", circom_code=code_vuln))
    assert not res_vuln.is_secure
    assert "secret_val" in res_vuln.vulnerable_signals
    assert res_vuln.status == "REJECTED_ZK_PUBLIC_INPUT_LEAKAGE"

    monkeypatch.setenv("PI_ZK_PUBLIC_INPUT_LEAKAGE_STRICT_MODE", "false")
    res_warn = agent.audit_public_input_leakage(ZKPublicInputLeakageInput(file_path="circuit.circom", circom_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_ZK_PUBLIC_INPUT_LEAKAGE"

    code_safe = """
    template Safe() {
        signal input public_val;
        signal input commitment;
        public_val <-- commitment;
    }
    """
    res_safe = agent.audit_public_input_leakage(ZKPublicInputLeakageInput(file_path="circuit.circom", circom_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 88. PiZKNonPrimeFieldRangeSentry Verification
# =====================================================================
def test_zk_non_prime_field_range_sentry(monkeypatch):
    agent = PiZKNonPrimeFieldRangeSentry()

    code_vuln = """
    template Large() {
        signal input a;
        a === 21888242871839275222246405745257275088548364400416034343698204186575808495618;
    }
    """
    res_vuln = agent.audit_non_prime_range(ZKNonPrimeFieldRangeInput(file_path="circuit.circom", circom_code=code_vuln))
    assert not res_vuln.is_secure
    assert "21888242871839275222246405745257275088548364400416034343698204186575808495618" in res_vuln.vulnerable_signals
    assert res_vuln.status == "REJECTED_ZK_NON_PRIME_FIELD"

    monkeypatch.setenv("PI_ZK_NON_PRIME_FIELD_STRICT_MODE", "false")
    res_warn = agent.audit_non_prime_range(ZKNonPrimeFieldRangeInput(file_path="circuit.circom", circom_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_ZK_NON_PRIME_FIELD"

    code_safe = """
    template Small() {
        signal input a;
        a === 1234567890123;
    }
    """
    res_safe = agent.audit_non_prime_range(ZKNonPrimeFieldRangeInput(file_path="circuit.circom", circom_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 89. PiZKUnusedConstraintVariables Verification
# =====================================================================
def test_zk_unused_constraint_variables(monkeypatch):
    agent = PiZKUnusedConstraintVariables()

    code_vuln = """
    template Unused() {
        signal input a;
        signal input b;
        signal output c;
        c <-- a + b;
    }
    """
    res_vuln = agent.audit_unused_variables(ZKUnusedConstraintInput(file_path="circuit.circom", circom_code=code_vuln))
    assert not res_vuln.is_secure
    assert "c" in res_vuln.vulnerable_signals
    assert res_vuln.status == "REJECTED_ZK_UNUSED_CONSTRAINT"

    monkeypatch.setenv("PI_ZK_UNUSED_CONSTRAINT_STRICT_MODE", "false")
    res_warn = agent.audit_unused_variables(ZKUnusedConstraintInput(file_path="circuit.circom", circom_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_ZK_UNUSED_CONSTRAINT"

    code_safe = """
    template Safe() {
        signal input a;
        signal input b;
        signal output c;
        c <== a + b;
    }
    """
    res_safe = agent.audit_unused_variables(ZKUnusedConstraintInput(file_path="circuit.circom", circom_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 90. PiZKProofForgingValidationSentry Verification
# =====================================================================
def test_zk_proof_forging_validation_sentry(monkeypatch):
    agent = PiZKProofForgingValidationSentry()

    code_vuln = """
    template verifyProof() {
        signal input in;
    }
    """
    res_vuln = agent.audit_proof_forging(ZKProofForgingValidationInput(file_path="circuit.circom", circom_code=code_vuln))
    assert not res_vuln.is_secure
    assert "verifyProof" in res_vuln.vulnerable_signals
    assert res_vuln.status == "REJECTED_ZK_PROOF_FORGING"

    monkeypatch.setenv("PI_ZK_PROOF_FORGING_STRICT_MODE", "false")
    res_warn = agent.audit_proof_forging(ZKProofForgingValidationInput(file_path="circuit.circom", circom_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_ZK_PROOF_FORGING"

    code_safe = """
    template verifyProof() {
        signal input in;
        signal input commitment;
    }
    """
    res_safe = agent.audit_proof_forging(ZKProofForgingValidationInput(file_path="circuit.circom", circom_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"
