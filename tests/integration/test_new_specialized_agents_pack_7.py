"""Integration tests for the 10 additional highly specialized dual-use PI micro-agents (Cohort 7: Agents 71-80)."""

from __future__ import annotations

import pytest

from pi_micro_agents import (
    ConstantPragmaInput,
    ERC20SafeApproveInput,
    PiRustSolanaAccountDataValidation,
    PiRustSolanaArithmeticOverflowCheck,
    PiRustSolanaCPIInstructionSentry,
    PiRustSolanaMissingSignerAssert,
    PiRustSolanaOwnerVerificationGuard,
    PiSolidityConstantPragmaValidation,
    PiSolidityERC20SafeApproveAuditor,
    PiSolidityProxyCallTargetCheck,
    PiSolidityUndeclaredReturnVariableSentry,
    PiSolidityYulMemoryOffsetAudit,
    ProxyCallTargetInput,
    SolanaAccountDataInput,
    SolanaArithmeticOverflowInput,
    SolanaCPIInstructionInput,
    SolanaMissingSignerInput,
    SolanaOwnerVerificationInput,
    UndeclaredReturnVariableInput,
    YulMemoryOffsetInput,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean test environment variables before each test runs."""
    monkeypatch.delenv("PI_ERC20_SAFE_APPROVE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_UNDECLARED_RETURN_VARIABLE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_YUL_MEMORY_OFFSET_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_PROXY_CALL_TARGET_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_CONSTANT_PRAGMA_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_SOLANA_ACCOUNT_DATA_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_SOLANA_MISSING_SIGNER_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_SOLANA_ARITHMETIC_OVERFLOW_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_SOLANA_OWNER_VERIFICATION_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_SOLANA_CPI_INSTRUCTION_STRICT_MODE", raising=False)


# =====================================================================
# 71. PiSolidityERC20SafeApproveAuditor Verification
# =====================================================================
def test_solidity_erc20_safe_approve_auditor(monkeypatch):
    agent = PiSolidityERC20SafeApproveAuditor()

    code_vuln = """
    contract Vulnerable {
        IERC20 public token;
        function approveSpender(address spender, uint amount) public {
            token.approve(spender, amount);
        }
    }
    """
    res_vuln = agent.audit_safe_approve(ERC20SafeApproveInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert "approveSpender" in res_vuln.vulnerable_functions
    assert res_vuln.status == "REJECTED_ERC20_SAFE_APPROVE"

    monkeypatch.setenv("PI_ERC20_SAFE_APPROVE_STRICT_MODE", "false")
    res_warn = agent.audit_safe_approve(ERC20SafeApproveInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_ERC20_SAFE_APPROVE"

    code_safe = """
    contract Safe {
        IERC20 public token;
        function approveSpender(address spender, uint amount) public {
            token.safeApprove(spender, amount);
        }
    }
    """
    res_safe = agent.audit_safe_approve(ERC20SafeApproveInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 72. PiSolidityUndeclaredReturnVariableSentry Verification
# =====================================================================
def test_solidity_undeclared_return_variable_sentry(monkeypatch):
    agent = PiSolidityUndeclaredReturnVariableSentry()

    code_vuln = """
    contract Vulnerable {
        function compute(uint a) public pure returns (uint val) {
            uint temp = a + 10;
        }
    }
    """
    res_vuln = agent.audit_undeclared_returns(
        UndeclaredReturnVariableInput(file_path="Vulnerable.sol", solidity_code=code_vuln)
    )
    assert not res_vuln.is_secure
    assert "compute" in res_vuln.vulnerable_functions
    assert res_vuln.status == "REJECTED_UNDECLARED_RETURN_VARIABLE"

    monkeypatch.setenv("PI_UNDECLARED_RETURN_VARIABLE_STRICT_MODE", "false")
    res_warn = agent.audit_undeclared_returns(
        UndeclaredReturnVariableInput(file_path="Vulnerable.sol", solidity_code=code_vuln)
    )
    assert res_warn.is_secure
    assert res_warn.status == "WARN_UNDECLARED_RETURN_VARIABLE"

    code_safe = """
    contract Safe {
        function compute(uint a) public pure returns (uint val) {
            val = a + 10;
        }
    }
    """
    res_safe = agent.audit_undeclared_returns(
        UndeclaredReturnVariableInput(file_path="Safe.sol", solidity_code=code_safe)
    )
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 73. PiSolidityYulMemoryOffsetAudit Verification
# =====================================================================
def test_solidity_yul_memory_offset_audit(monkeypatch):
    agent = PiSolidityYulMemoryOffsetAudit()

    code_vuln = """
    contract Vulnerable {
        function overwrite() public pure {
            assembly {
                mstore(0x40, 100)
            }
        }
    }
    """
    res_vuln = agent.audit_yul_memory(YulMemoryOffsetInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert "overwrite" in res_vuln.vulnerable_functions
    assert res_vuln.status == "REJECTED_YUL_MEMORY_OFFSET"

    monkeypatch.setenv("PI_YUL_MEMORY_OFFSET_STRICT_MODE", "false")
    res_warn = agent.audit_yul_memory(YulMemoryOffsetInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_YUL_MEMORY_OFFSET"

    code_safe = """
    contract Safe {
        function useScratch() public pure {
            assembly {
                mstore(0x80, 100)
            }
        }
    }
    """
    res_safe = agent.audit_yul_memory(YulMemoryOffsetInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 74. PiSolidityProxyCallTargetCheck Verification
# =====================================================================
def test_solidity_proxy_call_target_check(monkeypatch):
    agent = PiSolidityProxyCallTargetCheck()

    code_vuln = """
    contract Vulnerable {
        function upgrade(address target) public {
            target.delegatecall(abi.encodeWithSignature("initialize()"));
        }
    }
    """
    res_vuln = agent.audit_proxy_target(ProxyCallTargetInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert "upgrade" in res_vuln.vulnerable_functions
    assert res_vuln.status == "REJECTED_PROXY_CALL_TARGET"

    monkeypatch.setenv("PI_PROXY_CALL_TARGET_STRICT_MODE", "false")
    res_warn = agent.audit_proxy_target(ProxyCallTargetInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_PROXY_CALL_TARGET"

    code_safe = """
    contract Safe {
        mapping(address => bool) public isWhitelisted;
        function upgrade(address target) public {
            require(isWhitelisted[target], "not whitelisted");
            target.delegatecall(abi.encodeWithSignature("initialize()"));
        }
    }
    """
    res_safe = agent.audit_proxy_target(ProxyCallTargetInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 75. PiSolidityConstantPragmaValidation Verification
# =====================================================================
def test_solidity_constant_pragma_validation(monkeypatch):
    agent = PiSolidityConstantPragmaValidation()

    code_vuln = """
    pragma solidity ^0.8.20;
    contract Vulnerable {}
    """
    res_vuln = agent.audit_constant_pragma(ConstantPragmaInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_CONSTANT_PRAGMA"

    monkeypatch.setenv("PI_CONSTANT_PRAGMA_STRICT_MODE", "false")
    res_warn = agent.audit_constant_pragma(ConstantPragmaInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_CONSTANT_PRAGMA"

    code_safe = """
    pragma solidity 0.8.20;
    contract Safe {}
    """
    res_safe = agent.audit_constant_pragma(ConstantPragmaInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 76. PiRustSolanaAccountDataValidation Verification
# =====================================================================
def test_rust_solana_account_data_validation(monkeypatch):
    agent = PiRustSolanaAccountDataValidation()

    code_vuln = """
    pub fn process(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let account = next_account_info(accounts_iter)?;
        let data = account.try_borrow_data()?;
    }
    """
    res_vuln = agent.audit_account_data(SolanaAccountDataInput(file_path="lib.rs", rust_code=code_vuln))
    assert not res_vuln.is_secure
    assert "process" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_SOLANA_ACCOUNT_DATA"

    monkeypatch.setenv("PI_SOLANA_ACCOUNT_DATA_STRICT_MODE", "false")
    res_warn = agent.audit_account_data(SolanaAccountDataInput(file_path="lib.rs", rust_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_SOLANA_ACCOUNT_DATA"

    code_safe = """
    pub fn process(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let account = next_account_info(accounts_iter)?;
        assert!(account.data_len() >= 10);
        let data = account.try_borrow_data()?;
    }
    """
    res_safe = agent.audit_account_data(SolanaAccountDataInput(file_path="lib.rs", rust_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 77. PiRustSolanaMissingSignerAssert Verification
# =====================================================================
def test_rust_solana_missing_signer_assert(monkeypatch):
    agent = PiRustSolanaMissingSignerAssert()

    code_vuln = """
    pub fn process(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let user_info = next_account_info(accounts)?;
    }
    """
    res_vuln = agent.audit_missing_signer(SolanaMissingSignerInput(file_path="lib.rs", rust_code=code_vuln))
    assert not res_vuln.is_secure
    assert "process" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_SOLANA_MISSING_SIGNER"

    monkeypatch.setenv("PI_SOLANA_MISSING_SIGNER_STRICT_MODE", "false")
    res_warn = agent.audit_missing_signer(SolanaMissingSignerInput(file_path="lib.rs", rust_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_SOLANA_MISSING_SIGNER"

    code_safe = """
    pub fn process(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let user_info = next_account_info(accounts)?;
        if !user_info.is_signer {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }
    """
    res_safe = agent.audit_missing_signer(SolanaMissingSignerInput(file_path="lib.rs", rust_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 78. PiRustSolanaArithmeticOverflowCheck Verification
# =====================================================================
def test_rust_solana_arithmetic_overflow_check(monkeypatch):
    agent = PiRustSolanaArithmeticOverflowCheck()

    code_vuln = """
    pub fn process() {
        let total = amount + fee;
    }
    """
    res_vuln = agent.audit_arithmetic_overflow(SolanaArithmeticOverflowInput(file_path="lib.rs", rust_code=code_vuln))
    assert not res_vuln.is_secure
    assert "Line 3" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_SOLANA_ARITHMETIC_OVERFLOW"

    monkeypatch.setenv("PI_SOLANA_ARITHMETIC_OVERFLOW_STRICT_MODE", "false")
    res_warn = agent.audit_arithmetic_overflow(SolanaArithmeticOverflowInput(file_path="lib.rs", rust_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_SOLANA_ARITHMETIC_OVERFLOW"

    code_safe = """
    pub fn process() {
        let total = amount.checked_add(fee)?;
    }
    """
    res_safe = agent.audit_arithmetic_overflow(SolanaArithmeticOverflowInput(file_path="lib.rs", rust_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 79. PiRustSolanaOwnerVerificationGuard Verification
# =====================================================================
def test_rust_solana_owner_verification_guard(monkeypatch):
    agent = PiRustSolanaOwnerVerificationGuard()

    code_vuln = """
    pub fn process(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let vault = next_account_info(accounts)?;
    }
    """
    res_vuln = agent.audit_owner_verification(SolanaOwnerVerificationInput(file_path="lib.rs", rust_code=code_vuln))
    assert not res_vuln.is_secure
    assert "process" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_SOLANA_OWNER_VERIFICATION"

    monkeypatch.setenv("PI_SOLANA_OWNER_VERIFICATION_STRICT_MODE", "false")
    res_warn = agent.audit_owner_verification(SolanaOwnerVerificationInput(file_path="lib.rs", rust_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_SOLANA_OWNER_VERIFICATION"

    code_safe = """
    pub fn process(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        let vault = next_account_info(accounts)?;
        if vault.owner != program_id {
            return Err(ProgramError::IncorrectProgramId);
        }
    }
    """
    res_safe = agent.audit_owner_verification(SolanaOwnerVerificationInput(file_path="lib.rs", rust_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 80. PiRustSolanaCPIInstructionSentry Verification
# =====================================================================
def test_rust_solana_cpi_instruction_sentry(monkeypatch):
    agent = PiRustSolanaCPIInstructionSentry()

    code_vuln = """
    pub fn process_cpi(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        invoke(&instruction, accounts)?;
    }
    """
    res_vuln = agent.audit_cpi_instruction(SolanaCPIInstructionInput(file_path="lib.rs", rust_code=code_vuln))
    assert not res_vuln.is_secure
    assert "process_cpi" in res_vuln.vulnerable_elements
    assert res_vuln.status == "REJECTED_SOLANA_CPI_INSTRUCTION"

    monkeypatch.setenv("PI_SOLANA_CPI_INSTRUCTION_STRICT_MODE", "false")
    res_warn = agent.audit_cpi_instruction(SolanaCPIInstructionInput(file_path="lib.rs", rust_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_SOLANA_CPI_INSTRUCTION"

    code_safe = """
    pub fn process_cpi(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
        if program.key == &expected_id {
            invoke(&instruction, accounts)?;
        }
    }
    """
    res_safe = agent.audit_cpi_instruction(SolanaCPIInstructionInput(file_path="lib.rs", rust_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"
