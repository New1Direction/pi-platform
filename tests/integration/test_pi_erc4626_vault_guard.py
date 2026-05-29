"""Integration tests for PiERC4626VaultGuard — tokenized vault compliance agent."""

from pi_micro_agents.pi_erc4626_vault_guard import (
    PiERC4626VaultGuard,
    VaultGuardInput,
    VaultGuardOutput,
)

# ── Fixtures ───────────────────────────────────────────────────────────────

COMPLIANT_VAULT = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

contract SafeYieldVault is ERC4626 {
    // Virtual shares protection against inflation attacks
    function _decimalsOffset() internal pure override returns (uint8) { return 3; }

    function asset() public view override returns (address) { return address(_asset); }
    function totalAssets() public view override returns (uint256) { return _totalAssets(); }
    function convertToShares(uint256 assets) public view override returns (uint256) {
        return mulDiv(assets, totalSupply() + 10 ** _decimalsOffset(), totalAssets() + 1);
    }
    function convertToAssets(uint256 shares) public view override returns (uint256) {
        return mulDiv(shares, totalAssets() + 1, totalSupply() + 10 ** _decimalsOffset());
    }
    function maxDeposit(address) public pure override returns (uint256) { return type(uint256).max; }
    function previewDeposit(uint256 assets) public view override returns (uint256) { return convertToShares(assets); }
    function deposit(uint256 assets, address receiver) public override returns (uint256) {
        require(assets <= maxDeposit(receiver), "exceeds max");
        uint256 shares = previewDeposit(assets);
        _deposit(msg.sender, receiver, assets, shares);
        return shares;
    }
    function maxMint(address) public pure override returns (uint256) { return type(uint256).max; }
    function mint(uint256 shares, address receiver) public override returns (uint256) {
        require(shares <= maxMint(receiver), "exceeds max");
        uint256 assets = previewMint(shares);
        _deposit(msg.sender, receiver, assets, shares);
        return assets;
    }
    function maxWithdraw(address owner) public view override returns (uint256) { return convertToAssets(balanceOf(owner)); }
    function previewWithdraw(uint256 assets) public view override returns (uint256) {
        return mulDivUp(assets, totalSupply() + 10 ** _decimalsOffset(), totalAssets() + 1);
    }
    function withdraw(uint256 assets, address receiver, address owner) public override returns (uint256) {
        uint256 shares = previewWithdraw(assets);
        _withdraw(msg.sender, receiver, owner, assets, shares);
        return shares;
    }
    function maxRedeem(address owner) public view override returns (uint256) { return balanceOf(owner); }
    function previewRedeem(uint256 shares) public view override returns (uint256) { return convertToAssets(shares); }
    function redeem(uint256 shares, address receiver, address owner) public override returns (uint256) {
        uint256 assets = previewRedeem(shares);
        _withdraw(msg.sender, receiver, owner, assets, shares);
        return assets;
    }
    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);
}
"""

INFLATION_VULNERABLE_VAULT = """
pragma solidity ^0.8.0;

contract VulnerableVault {
    mapping(address => uint256) public shares;
    uint256 public totalAssets;
    uint256 public totalSupply;

    // NO virtual shares protection
    function convertToShares(uint256 assets) public view returns (uint256) {
        if (totalSupply == 0) return assets;
        return assets * totalSupply / totalAssets;  // rounds DOWN — no offset
    }
    function convertToAssets(uint256 _shares) public view returns (uint256) {
        if (totalSupply == 0) return _shares;
        return _shares * totalAssets / totalSupply;
    }
    function maxDeposit(address) public pure returns (uint256) { return type(uint256).max; }
    function previewDeposit(uint256 assets) public view returns (uint256) { return convertToShares(assets); }
    function deposit(uint256 assets, address receiver) public returns (uint256) {
        // No maxDeposit check
        uint256 _shares = previewDeposit(assets);
        shares[receiver] += _shares;
        totalSupply += _shares;
        return _shares;
    }
    function maxMint(address) public pure returns (uint256) { return type(uint256).max; }
    function mint(uint256 _shares, address receiver) public returns (uint256) {
        // No maxMint check
        shares[receiver] += _shares;
        totalSupply += _shares;
        return _shares;
    }
    function maxWithdraw(address owner) public view returns (uint256) { return convertToAssets(shares[owner]); }
    function previewWithdraw(uint256 assets) public view returns (uint256) {
        return assets * totalSupply / totalAssets;  // rounds DOWN — wrong!
    }
    function withdraw(uint256 assets, address receiver, address owner) public returns (uint256) { return 0; }
    function maxRedeem(address owner) public view returns (uint256) { return shares[owner]; }
    function previewRedeem(uint256 _shares) public view returns (uint256) { return convertToAssets(_shares); }
    function redeem(uint256 _shares, address receiver, address owner) public returns (uint256) { return 0; }
    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);
    function asset() public view returns (address) { return address(0); }
    function totalAssets() public view returns (uint256) { return totalAssets; }
}
"""

ROUNDING_ERROR_VAULT = """
pragma solidity ^0.8.0;

contract RoundingBadVault {
    uint256 public totalSupply;
    uint256 public total;

    function _decimalsOffset() internal pure returns (uint8) { return 3; }

    // Rounds UP in convertToShares — wrong! should round down
    function convertToShares(uint256 assets) public view returns (uint256) {
        return mulDivUp(assets, totalSupply + 10 ** _decimalsOffset(), total + 1);
    }
    // Rounds UP in convertToAssets — wrong! should round down
    function convertToAssets(uint256 shares) public view returns (uint256) {
        return mulDivUp(shares, total + 1, totalSupply + 10 ** _decimalsOffset());
    }
    function asset() public view returns (address) { return address(0); }
    function totalAssets() public view returns (uint256) { return total; }
    function maxDeposit(address) public pure returns (uint256) { return type(uint256).max; }
    function previewDeposit(uint256 assets) public view returns (uint256) { return convertToShares(assets); }
    function deposit(uint256 assets, address receiver) public returns (uint256) { require(assets <= maxDeposit(receiver), "x"); return 0; }
    function maxMint(address) public pure returns (uint256) { return type(uint256).max; }
    function mint(uint256 shares, address receiver) public returns (uint256) { require(shares <= maxMint(receiver), "x"); return 0; }
    function maxWithdraw(address) public view returns (uint256) { return 0; }
    function previewWithdraw(uint256 assets) public view returns (uint256) { return mulDivUp(assets, totalSupply, total); }
    function withdraw(uint256 a, address r, address o) public returns (uint256) { return 0; }
    function maxRedeem(address) public view returns (uint256) { return 0; }
    function previewRedeem(uint256 shares) public view returns (uint256) { return convertToAssets(shares); }
    function redeem(uint256 s, address r, address o) public returns (uint256) { return 0; }
    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);
}
"""

INCOMPLETE_INTERFACE = """
pragma solidity ^0.8.0;

contract IncompleteVault {
    // Only a few functions — missing most of the interface
    function deposit(uint256 assets, address receiver) public returns (uint256) { return 0; }
    function redeem(uint256 shares, address receiver, address owner) public returns (uint256) { return 0; }
    event Deposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
}
"""


# ── Tests: Mode 1 — Attack Surface Detection ───────────────────────────────


class TestERC4626VaultGuardMode1:
    def test_compliant_vault_passes(self) -> None:
        agent = PiERC4626VaultGuard()
        result = agent.audit_vault(
            VaultGuardInput(
                file_path="vault.sol",
                solidity_code=COMPLIANT_VAULT,
            )
        )
        assert isinstance(result, VaultGuardOutput)
        assert result.is_compliant is True
        assert result.attack_vectors == []
        assert result.rounding_violations == []
        assert result.status == "PASSED"

    def test_inflation_attack_detected(self) -> None:
        agent = PiERC4626VaultGuard()
        result = agent.audit_vault(
            VaultGuardInput(
                file_path="vault.sol",
                solidity_code=INFLATION_VULNERABLE_VAULT,
            )
        )
        assert isinstance(result, VaultGuardOutput)
        assert any("inflation" in v.lower() or "virtual" in v.lower() for v in result.attack_vectors)
        assert result.risk_score >= 80.0

    def test_rounding_errors_detected(self) -> None:
        agent = PiERC4626VaultGuard()
        result = agent.audit_vault(
            VaultGuardInput(
                file_path="vault.sol",
                solidity_code=ROUNDING_ERROR_VAULT,
            )
        )
        assert isinstance(result, VaultGuardOutput)
        assert len(result.rounding_violations) > 0
        assert any("convertToShares" in v or "convertToAssets" in v for v in result.rounding_violations)

    def test_output_is_pydantic_model(self) -> None:
        agent = PiERC4626VaultGuard()
        result = agent.audit_vault(
            VaultGuardInput(
                file_path="v.sol",
                solidity_code=COMPLIANT_VAULT,
            )
        )
        assert isinstance(result, VaultGuardOutput)
        assert hasattr(result, "is_compliant")
        assert hasattr(result, "attack_vectors")
        assert hasattr(result, "missing_functions")
        assert hasattr(result, "rounding_violations")
        assert hasattr(result, "risk_score")
        assert hasattr(result, "status")


# ── Tests: Mode 2 — Interface Compliance ──────────────────────────────────


class TestERC4626VaultGuardMode2:
    def test_missing_functions_flagged(self) -> None:
        agent = PiERC4626VaultGuard()
        result = agent.audit_vault(
            VaultGuardInput(
                file_path="vault.sol",
                solidity_code=INCOMPLETE_INTERFACE,
            )
        )
        assert isinstance(result, VaultGuardOutput)
        assert len(result.missing_functions) > 0
        # Should flag many missing functions
        assert any("totalAssets" in f or "convertToShares" in f or "asset" in f for f in result.missing_functions)

    def test_risk_score_bounded(self) -> None:
        for code in [COMPLIANT_VAULT, INFLATION_VULNERABLE_VAULT, ROUNDING_ERROR_VAULT]:
            agent = PiERC4626VaultGuard()
            result = agent.audit_vault(VaultGuardInput(file_path="v.sol", solidity_code=code))
            assert 0.0 <= result.risk_score <= 100.0

    def test_compliant_vault_no_missing_functions(self) -> None:
        agent = PiERC4626VaultGuard()
        result = agent.audit_vault(
            VaultGuardInput(
                file_path="vault.sol",
                solidity_code=COMPLIANT_VAULT,
            )
        )
        assert result.missing_functions == []


# ── Tests: Dual-Use & Serialization ───────────────────────────────────────


class TestERC4626VaultGuardDualUse:
    def test_model_dump_serializable(self) -> None:
        agent = PiERC4626VaultGuard()
        result = agent.audit_vault(
            VaultGuardInput(
                file_path="v.sol",
                solidity_code=COMPLIANT_VAULT,
            )
        )
        d = result.model_dump()
        assert "is_compliant" in d
        assert "risk_score" in d
        assert isinstance(d["attack_vectors"], list)

    def test_status_values_valid(self) -> None:
        valid_statuses = {"PASSED", "WARN_VAULT_RISK", "REJECTED_VAULT_RISK"}
        for code in [COMPLIANT_VAULT, INFLATION_VULNERABLE_VAULT, INCOMPLETE_INTERFACE]:
            agent = PiERC4626VaultGuard()
            result = agent.audit_vault(VaultGuardInput(file_path="v.sol", solidity_code=code))
            assert result.status in valid_statuses

    def test_risk_score_higher_for_critical_findings(self) -> None:
        agent = PiERC4626VaultGuard()
        clean_result = agent.audit_vault(VaultGuardInput(file_path="v.sol", solidity_code=COMPLIANT_VAULT))
        vuln_result = agent.audit_vault(VaultGuardInput(file_path="v.sol", solidity_code=INFLATION_VULNERABLE_VAULT))
        assert vuln_result.risk_score > clean_result.risk_score
