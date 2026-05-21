"""Integration tests for the 10 additional highly specialized dual-use PI micro-agents (Cohort 7: Agents 61-70)."""

from __future__ import annotations

import os
import pytest

from pi_micro_agents import (
    PiSolidityReentrancyGuardOverlapSentry,
    ReentrancyGuardOverlapInput,
    PiSolidityTxOriginCallCheckSentry,
    TxOriginCallCheckInput,
    PiSolidityArrayLengthMutationSentry,
    ArrayLengthMutationInput,
    PiSolidityExternalContractsReturnCheck,
    ExternalContractsReturnInput,
    PiSolidityUnboundedLoopsInStateMutation,
    UnboundedLoopsStateInput,
    PiSolidityDivideBeforeMultiplyAuditor,
    DivideBeforeMultiplyInput,
    PiSolidityInitializableGapSentry,
    InitializableGapInput,
    PiSoliditySelfdestructCodeEraseSentry,
    SelfdestructCodeEraseInput,
    PiSoliditySignatureOmittedReplaySentry,
    SignatureOmittedReplayInput,
    PiSolidityOwnerTimelockSentry,
    OwnerTimelockInput,
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean test environment variables before each test runs."""
    monkeypatch.delenv("PI_REENTRANCY_GUARD_OVERLAP_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_TX_ORIGIN_CALL_CHECK_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ARRAY_LENGTH_MUTATION_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_EXTERNAL_CONTRACTS_RETURN_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_UNBOUNDED_LOOPS_STATE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_DIVIDE_BEFORE_MULTIPLY_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_INITIALIZABLE_GAP_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_SELFDESTRUCT_CODE_ERASE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_SIGNATURE_OMITTED_REPLAY_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_OWNER_TIMELOCK_STRICT_MODE", raising=False)


# =====================================================================
# 61. PiSolidityReentrancyGuardOverlapSentry Verification
# =====================================================================
def test_solidity_reentrancy_guard_overlap_sentry(monkeypatch):
    agent = PiSolidityReentrancyGuardOverlapSentry()

    code_vuln = """
    contract Vulnerable {
        function withdraw() external nonReentrant lock {
            msg.sender.transfer(1 ether);
        }
    }
    """
    res_vuln = agent.audit_reentrancy_overlap(ReentrancyGuardOverlapInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert "withdraw" in res_vuln.vulnerable_functions
    assert res_vuln.status == "REJECTED_REENTRANCY_GUARD_OVERLAP"

    # Toggle warning mode
    monkeypatch.setenv("PI_REENTRANCY_GUARD_OVERLAP_STRICT_MODE", "false")
    res_warn = agent.audit_reentrancy_overlap(ReentrancyGuardOverlapInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_REENTRANCY_GUARD_OVERLAP"

    code_safe = """
    contract Safe {
        function withdraw() external nonReentrant {
            msg.sender.transfer(1 ether);
        }
    }
    """
    res_safe = agent.audit_reentrancy_overlap(ReentrancyGuardOverlapInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 62. PiSolidityTxOriginCallCheckSentry Verification
# =====================================================================
def test_solidity_tx_origin_call_check_sentry(monkeypatch):
    agent = PiSolidityTxOriginCallCheckSentry()

    code_vuln = """
    contract Vulnerable {
        function transfer(address to, uint amount) public {
            require(tx.origin == owner, "not owner");
            balances[to] += amount;
        }
    }
    """
    res_vuln = agent.audit_tx_origin_call(TxOriginCallCheckInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert any("transfer" in f for f in res_vuln.vulnerable_functions)
    assert res_vuln.status == "REJECTED_TX_ORIGIN_CALL_CHECK"

    # Toggle warning mode
    monkeypatch.setenv("PI_TX_ORIGIN_CALL_CHECK_STRICT_MODE", "false")
    res_warn = agent.audit_tx_origin_call(TxOriginCallCheckInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_TX_ORIGIN_CALL_CHECK"

    code_safe = """
    contract Safe {
        function transfer(address to, uint amount) public {
            require(msg.sender == owner, "not owner");
            balances[to] += amount;
        }
    }
    """
    res_safe = agent.audit_tx_origin_call(TxOriginCallCheckInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 63. PiSolidityArrayLengthMutationSentry Verification
# =====================================================================
def test_solidity_array_length_mutation_sentry(monkeypatch):
    agent = PiSolidityArrayLengthMutationSentry()

    code_vuln = """
    contract Vulnerable {
        uint[] public data;
        function corrupt(uint newlen) public {
            assembly {
                sstore(data.slot, newlen)
            }
            {
                // dummy to keep curly braces balanced
            }
        }
    }
    """
    res_vuln = agent.audit_array_length_mutation(ArrayLengthMutationInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert "corrupt" in res_vuln.vulnerable_functions
    assert res_vuln.status == "REJECTED_ARRAY_LENGTH_MUTATION"

    # Toggle warning mode
    monkeypatch.setenv("PI_ARRAY_LENGTH_MUTATION_STRICT_MODE", "false")
    res_warn = agent.audit_array_length_mutation(ArrayLengthMutationInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_ARRAY_LENGTH_MUTATION"

    code_safe = """
    contract Safe {
        uint[] public data;
        function update(uint val) public {
            data.push(val);
        }
    }
    """
    res_safe = agent.audit_array_length_mutation(ArrayLengthMutationInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 64. PiSolidityExternalContractsReturnCheck Verification
# =====================================================================
def test_solidity_external_contracts_return_check(monkeypatch):
    agent = PiSolidityExternalContractsReturnCheck()

    code_vuln = """
    contract Vulnerable {
        function callExternal(address target) public {
            target.call(abi.encodeWithSignature("foo()"));
        }
    }
    """
    res_vuln = agent.audit_external_returns(ExternalContractsReturnInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert "callExternal" in res_vuln.vulnerable_functions
    assert res_vuln.status == "REJECTED_EXTERNAL_CONTRACTS_RETURN"

    # Toggle warning mode
    monkeypatch.setenv("PI_EXTERNAL_CONTRACTS_RETURN_STRICT_MODE", "false")
    res_warn = agent.audit_external_returns(ExternalContractsReturnInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_EXTERNAL_CONTRACTS_RETURN"

    code_safe = """
    contract Safe {
        function callExternal(address target) public {
            (bool success, ) = target.call(abi.encodeWithSignature("foo()"));
            require(success, "call failed");
        }
    }
    """
    res_safe = agent.audit_external_returns(ExternalContractsReturnInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 65. PiSolidityUnboundedLoopsInStateMutation Verification
# =====================================================================
def test_solidity_unbounded_loops_in_state_mutation(monkeypatch):
    agent = PiSolidityUnboundedLoopsInStateMutation()

    code_vuln = """
    contract Vulnerable {
        uint[] public users;
        function updateAll() public {
            for (uint i = 0; i < users.length; i++) {
                state[users[i]] = true;
            }
            {
                // dummy
            }
        }
    }
    """
    res_vuln = agent.audit_unbounded_loops(UnboundedLoopsStateInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert "updateAll" in res_vuln.vulnerable_functions
    assert res_vuln.status == "REJECTED_UNBOUNDED_LOOPS_STATE"

    # Toggle warning mode
    monkeypatch.setenv("PI_UNBOUNDED_LOOPS_STATE_STRICT_MODE", "false")
    res_warn = agent.audit_unbounded_loops(UnboundedLoopsStateInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_UNBOUNDED_LOOPS_STATE"

    code_safe = """
    contract Safe {
        uint[] public users;
        function updateRange(uint start, uint end) public {
            require(end <= users.length && end - start < 100);
            for (uint i = start; i < end; i++) {
                state[users[i]] = true;
            }
        }
    }
    """
    res_safe = agent.audit_unbounded_loops(UnboundedLoopsStateInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 66. PiSolidityDivideBeforeMultiplyAuditor Verification
# =====================================================================
def test_solidity_divide_before_multiply_auditor(monkeypatch):
    agent = PiSolidityDivideBeforeMultiplyAuditor()

    code_vuln = """
    contract Vulnerable {
        function calculate(uint a, uint b, uint c) public pure returns (uint) {
            return a / b * c;
        }
    }
    """
    res_vuln = agent.audit_divide_multiply(DivideBeforeMultiplyInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert "calculate" in res_vuln.vulnerable_functions
    assert res_vuln.status == "REJECTED_DIVIDE_BEFORE_MULTIPLY"

    # Toggle warning mode
    monkeypatch.setenv("PI_DIVIDE_BEFORE_MULTIPLY_STRICT_MODE", "false")
    res_warn = agent.audit_divide_multiply(DivideBeforeMultiplyInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_DIVIDE_BEFORE_MULTIPLY"

    code_safe = """
    contract Safe {
        function calculate(uint a, uint b, uint c) public pure returns (uint) {
            return (a * c) / b;
        }
    }
    """
    res_safe = agent.audit_divide_multiply(DivideBeforeMultiplyInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 67. PiSolidityInitializableGapSentry Verification
# =====================================================================
def test_solidity_initializable_gap_sentry(monkeypatch):
    agent = PiSolidityInitializableGapSentry()

    code_vuln = """
    contract Vulnerable is Initializable {
        uint256 public value;
        // missing gap
    }
    """
    res_vuln = agent.audit_initializable_gap(InitializableGapInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert "Vulnerable" in res_vuln.vulnerable_contracts
    assert res_vuln.status == "REJECTED_INITIALIZABLE_GAP"

    # Toggle warning mode
    monkeypatch.setenv("PI_INITIALIZABLE_GAP_STRICT_MODE", "false")
    res_warn = agent.audit_initializable_gap(InitializableGapInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_INITIALIZABLE_GAP"

    code_safe = """
    contract Safe is Initializable {
        uint256 public value;
        uint256[50] private __gap;
    }
    """
    res_safe = agent.audit_initializable_gap(InitializableGapInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 68. PiSoliditySelfdestructCodeEraseSentry Verification
# =====================================================================
def test_solidity_selfdestruct_code_erase_sentry(monkeypatch):
    agent = PiSoliditySelfdestructCodeEraseSentry()

    code_vuln = """
    contract Vulnerable {
        function kill() public {
            selfdestruct(payable(msg.sender));
        }
    }
    """
    res_vuln = agent.audit_selfdestruct_usage(SelfdestructCodeEraseInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert "kill" in res_vuln.vulnerable_functions
    assert res_vuln.status == "REJECTED_SELFDESTRUCT_CODE_ERASE"

    # Toggle warning mode
    monkeypatch.setenv("PI_SELFDESTRUCT_CODE_ERASE_STRICT_MODE", "false")
    res_warn = agent.audit_selfdestruct_usage(SelfdestructCodeEraseInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_SELFDESTRUCT_CODE_ERASE"

    code_safe = """
    contract Safe {
        function close() public {
            // safe logic
        }
    }
    """
    res_safe = agent.audit_selfdestruct_usage(SelfdestructCodeEraseInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 69. PiSoliditySignatureOmittedReplaySentry Verification
# =====================================================================
def test_solidity_signature_omitted_replay_sentry(monkeypatch):
    agent = PiSoliditySignatureOmittedReplaySentry()

    code_vuln = """
    contract Vulnerable {
        function hashMessage(address user, uint amount) public pure returns (bytes32) {
            return keccak256(abi.encodePacked(user, amount));
        }
    }
    """
    res_vuln = agent.audit_signature_replay(SignatureOmittedReplayInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert "hashMessage" in res_vuln.vulnerable_functions
    assert res_vuln.status == "REJECTED_SIGNATURE_OMITTED_REPLAY"

    # Toggle warning mode
    monkeypatch.setenv("PI_SIGNATURE_OMITTED_REPLAY_STRICT_MODE", "false")
    res_warn = agent.audit_signature_replay(SignatureOmittedReplayInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_SIGNATURE_OMITTED_REPLAY"

    code_safe = """
    contract Safe {
        function hashMessage(address user, uint amount, uint nonce) public view returns (bytes32) {
            return keccak256(abi.encodePacked(user, amount, nonce, block.chainid, address(this)));
        }
    }
    """
    res_safe = agent.audit_signature_replay(SignatureOmittedReplayInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 70. PiSolidityOwnerTimelockSentry Verification
# =====================================================================
def test_solidity_owner_timelock_sentry(monkeypatch):
    agent = PiSolidityOwnerTimelockSentry()

    code_vuln = """
    contract Vulnerable {
        function setRates(uint newRate) public onlyOwner {
            rate = newRate;
        }
    }
    """
    res_vuln = agent.audit_owner_timelock(OwnerTimelockInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert not res_vuln.is_secure
    assert "setRates" in res_vuln.vulnerable_functions
    assert res_vuln.status == "REJECTED_OWNER_TIMELOCK"

    # Toggle warning mode
    monkeypatch.setenv("PI_OWNER_TIMELOCK_STRICT_MODE", "false")
    res_warn = agent.audit_owner_timelock(OwnerTimelockInput(file_path="Vulnerable.sol", solidity_code=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_OWNER_TIMELOCK"

    code_safe = """
    contract Safe {
        function setRates(uint newRate) public onlyTimelock {
            rate = newRate;
        }
    }
    """
    res_safe = agent.audit_owner_timelock(OwnerTimelockInput(file_path="Safe.sol", solidity_code=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"
