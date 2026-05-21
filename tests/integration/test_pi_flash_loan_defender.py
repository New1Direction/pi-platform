"""Integration tests for the PiFlashLoanDefender micro-agent and its Orchestrator consensus execution."""

from __future__ import annotations

import os
import pytest

from pi_micro_agents.pi_flash_loan_defender import (
    PiFlashLoanDefender,
    FlashLoanInput,
    FlashLoanOutput,
    is_strict_mode,
)
from pi_micro_agents.pi_orchestrator import PiOrchestrator, OrchestratorInput


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean environment variable setup for each test run."""
    monkeypatch.delenv("PI_FLASH_LOAN_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ORCHESTRATOR_STRICT_MODE", raising=False)


# =====================================================================
# Test 1: Classical Spot-Price Reserve Division (Vulnerable AMM Price Lookup)
# =====================================================================
def test_flash_loan_vulnerable_spot_price_contract():
    """Verify that calculating token prices directly using pair reserves / division is flagged."""
    agent = PiFlashLoanDefender()

    solidity_code = """
    contract VulnerableAMMPriceOracle {
        address public pair;

        constructor(address _pair) {
            pair = _pair;
        }

        function getPrice() public view returns (uint256) {
            (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast) = IUniswapV2Pair(pair).getReserves();
            // Division involving reserve variables (vulnerable spot calculation)
            return uint256(reserve0) / reserve1;
        }
    }
    """
    inp = FlashLoanInput(
        file_path="VulnerableAMMPriceOracle.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_flash_loan(inp)

    assert out.is_secure is False
    assert "getPrice" in out.vulnerable_functions
    assert out.risk_score == 95.0
    assert out.status == "REJECTED_FLASH_LOAN_VULNERABILITY"
    assert len(out.flagged_findings) >= 1
    assert "calculates asset exchange rate directly via spot reserves" in out.flagged_findings[0]


# =====================================================================
# Test 2: Safe Oracle Protection (TWAP or Chainlink Integration)
# =====================================================================
def test_flash_loan_safe_oracle_contract():
    """Verify that a contract utilizing Chainlink latestRoundData or TWAP consult passes audit."""
    agent = PiFlashLoanDefender()

    solidity_code = """
    contract SecurePriceOracle {
        IAggregatorV3Interface public priceFeed;

        constructor(address _feed) {
            priceFeed = IAggregatorV3Interface(_feed);
        }

        function getPrice() public view returns (uint256) {
            // Uses Chainlink decentralized pricing feeds
            (, int256 price, , , ) = priceFeed.latestRoundData();
            return uint256(price);
        }
    }
    """
    inp = FlashLoanInput(
        file_path="SecurePriceOracle.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_flash_loan(inp)

    assert out.is_secure is True
    assert out.risk_score == 0.0
    assert out.status == "PASSED"
    assert len(out.vulnerable_functions) == 0
    assert len(out.flagged_findings) == 0


# =====================================================================
# Test 3: Direct Balance-Pricing Lookup (Vulnerable to Token Inflation)
# =====================================================================
def test_flash_loan_direct_balance_pricing_vulnerable():
    """Verify that querying balanceOf combined with pricing variables is flagged."""
    agent = PiFlashLoanDefender()

    solidity_code = """
    contract VulnerableBalancePricing {
        IERC20 public token;

        constructor(address _token) {
            token = IERC20(_token);
        }

        function getRate() public view returns (uint256) {
            // Balance check paired with rate/price mapping (highly susceptible to flash loan swap inflations)
            uint256 balance = token.balanceOf(address(this));
            return balance;
        }
    }
    """
    inp = FlashLoanInput(
        file_path="VulnerableBalancePricing.sol",
        solidity_code=solidity_code,
        check_level="STRICT"
    )

    out = agent.audit_flash_loan(inp)

    assert out.is_secure is False
    assert "getRate" in out.vulnerable_functions
    assert out.risk_score == 95.0
    assert out.status == "REJECTED_FLASH_LOAN_VULNERABILITY"
    assert len(out.flagged_findings) >= 1
    assert "calculates asset value using direct contract token balance checks" in out.flagged_findings[0]


# =====================================================================
# Test 4: Orchestrator Routing & Consensus Passed
# =====================================================================
def test_orchestrator_flash_loan_consensus_passed(monkeypatch):
    """Verify NLP intent routing to PiFlashLoanDefender resolves low-divergence majority votes."""
    monkeypatch.setenv("PI_FLASH_LOAN_STRICT_MODE", "true")
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    orchestrator = PiOrchestrator()

    solidity_code = """
    contract VulnerableAMM {
        function getPrice() public view returns (uint256) {
            return reserve0 / reserve1;
        }
    }
    """

    mock_consensus_runs = [
        {
            "is_secure": False,
            "vulnerable_functions": ["getPrice"],
            "flagged_findings": ["Direct reserve division"],
            "risk_score": 95.0,
            "status": "REJECTED_FLASH_LOAN_VULNERABILITY"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["getPrice"],
            "flagged_findings": ["Direct reserve division"],
            "risk_score": 95.0,
            "status": "REJECTED_FLASH_LOAN_VULNERABILITY"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["getPrice"],
            "flagged_findings": ["Direct reserve division"],
            "risk_score": 95.0,
            "status": "REJECTED_FLASH_LOAN_VULNERABILITY"
        }
    ]

    inp = OrchestratorInput(
        goal="flash loan check on VulnerableAMM.sol to secure against oracle manipulation",
        context={
            "file_path": "VulnerableAMM.sol",
            "solidity_code": solidity_code,
            "mock_consensus_runs": mock_consensus_runs
        }
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert res.risk_score == 95.0
    assert "PiFlashLoanDefender" in res.routed_agent
    assert "Consensus Passed" in res.output_summary
    assert "REJECTED_FLASH_LOAN_VULNERABILITY" in res.output_summary
    assert "consensus_telemetry" in res.result_details
    assert res.result_details["consensus_telemetry"]["status"] == "CONSENSUS_PASSED"


# =====================================================================
# Test 5: Orchestrator Consensus High Divergence / Split Vote
# =====================================================================
def test_orchestrator_flash_loan_consensus_failed_divergence(monkeypatch):
    """Verify that split vote high-divergence output triggers fail-shut and blocks execution."""
    monkeypatch.setenv("PI_ORCHESTRATOR_STRICT_MODE", "true")

    from pi_semantic_radius.consensus_breaker import PiConsensusBreaker, DivergenceReport
    def mock_evaluate_consensus(self, prompt, responses):
        return DivergenceReport(
            prompt=prompt,
            responses=responses,
            semantic_divergence=85.0,
            structural_divergence=0.0,
            consensus_divergence_score=85.0,
            is_broken=True
        )
    monkeypatch.setattr(PiConsensusBreaker, "evaluate_consensus", mock_evaluate_consensus)

    orchestrator = PiOrchestrator()

    solidity_code = """
    contract VulnerableAMM {
        function getPrice() public view returns (uint256) {
            return reserve0 / reserve1;
        }
    }
    """

    mock_consensus_runs = [
        {
            "is_secure": True,
            "vulnerable_functions": [],
            "flagged_findings": [],
            "risk_score": 0.0,
            "status": "PASSED"
        },
        {
            "is_secure": False,
            "vulnerable_functions": ["getPrice"],
            "flagged_findings": ["Direct reserve division"],
            "risk_score": 95.0,
            "status": "REJECTED_FLASH_LOAN_VULNERABILITY"
        },
        {
            "is_secure": True,
            "vulnerable_functions": [],
            "flagged_findings": [],
            "risk_score": 0.0,
            "status": "PASSED"
        }
    ]

    inp = OrchestratorInput(
        goal="flash loan check on VulnerableAMM.sol",
        context={
            "file_path": "VulnerableAMM.sol",
            "solidity_code": solidity_code,
            "mock_consensus_runs": mock_consensus_runs
        }
    )
    res = orchestrator.execute_goal(inp)

    assert res.success is False
    assert "consensus coordination alarm" in res.output_summary or "REJECTED_DIVERGENCE_ALARM" in res.output_summary
    assert "consensus_telemetry" in res.result_details
    assert res.result_details["consensus_telemetry"]["status"] == "REJECTED_DIVERGENCE_ALARM"
    assert res.result_details["consensus_telemetry"]["divergence_score"] >= 60.0
