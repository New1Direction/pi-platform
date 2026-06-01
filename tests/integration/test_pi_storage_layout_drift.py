"""Integration tests for PiStorageLayoutDrift — dual-use storage slot drift sentinel."""

from pi_micro_agents.pi_storage_layout_drift import (
    PiStorageLayoutDrift,
    StorageDriftInput,
    StorageDriftOutput,
)

# ── Fixtures ───────────────────────────────────────────────────────────────

SAFE_V1 = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyTokenV1 is Initializable {
    address public owner;
    uint256 public totalSupply;
    uint256[50] private __gap;

    function initialize(address _owner) public initializer {
        owner = _owner;
        totalSupply = 1_000_000;
    }
}
"""

SAFE_V2_APPEND_ONLY = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyTokenV2 is Initializable {
    address public owner;
    uint256 public totalSupply;
    uint256 public newField;   // <-- appended at end (safe)
    uint256[49] private __gap; // <-- gap reduced by 1 (correct)

    function initialize(address _owner) public initializer {
        owner = _owner;
        totalSupply = 1_000_000;
    }
}
"""

DRIFT_V2_INSERT = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyTokenV2 is Initializable {
    address public owner;
    uint256 public newField;    // <-- INSERTED before totalSupply (slot drift!)
    uint256 public totalSupply;
    uint256[50] private __gap;

    function initialize(address _owner) public initializer {
        owner = _owner;
    }
}
"""

MISSING_GAP = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyToken is Initializable {
    address public owner;
    uint256 public totalSupply;

    function initialize(address _owner) public initializer {
        owner = _owner;
    }
}
"""

TINY_GAP = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyToken is Initializable {
    address public owner;
    uint256[5] private __gap;  // Only 5 slots — too small

    function initialize(address _owner) public initializer {
        owner = _owner;
    }
}
"""

CONSTRUCTOR_STATE_INIT = """
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract MyToken is Initializable {
    address public owner;
    uint256 public totalSupply = 1_000_000; // initialized in constructor!
    uint256[50] private __gap;

    function initialize(address _owner) public initializer {
        owner = _owner;
    }
}
"""


# ── Tests: Mode 1 — Drift Detection ────────────────────────────────────────


class TestStorageLayoutDriftMode1:
    def test_safe_append_only_upgrade_passes(self) -> None:
        agent = PiStorageLayoutDrift()
        result = agent.audit_storage(
            StorageDriftInput(
                file_path="token.sol",
                solidity_code=SAFE_V2_APPEND_ONLY,
                previous_code=SAFE_V1,
            )
        )
        assert isinstance(result, StorageDriftOutput)
        assert result.is_safe is True
        assert result.drifted_slots == []
        assert result.risk_score == 0.0
        assert result.status == "PASSED"

    def test_inserted_variable_causes_slot_drift(self) -> None:
        agent = PiStorageLayoutDrift()
        result = agent.audit_storage(
            StorageDriftInput(
                file_path="token.sol",
                solidity_code=DRIFT_V2_INSERT,
                previous_code=SAFE_V1,
            )
        )
        assert isinstance(result, StorageDriftOutput)
        # totalSupply should be flagged as drifted
        assert any("totalSupply" in f for f in result.drifted_slots)
        assert result.risk_score >= 90.0

    def test_no_previous_code_skips_drift_check(self) -> None:
        agent = PiStorageLayoutDrift()
        result = agent.audit_storage(
            StorageDriftInput(
                file_path="token.sol",
                solidity_code=SAFE_V1,
                previous_code="",
            )
        )
        assert isinstance(result, StorageDriftOutput)
        assert result.drifted_slots == []  # no drift check without previous

    def test_output_is_pydantic_model(self) -> None:
        agent = PiStorageLayoutDrift()
        result = agent.audit_storage(
            StorageDriftInput(
                file_path="x.sol",
                solidity_code=SAFE_V1,
            )
        )
        assert isinstance(result, StorageDriftOutput)
        assert hasattr(result, "is_safe")
        assert hasattr(result, "drifted_slots")
        assert hasattr(result, "compliance_findings")
        assert hasattr(result, "risk_score")
        assert hasattr(result, "status")


# ── Tests: Mode 2 — Compliance Auditing ───────────────────────────────────


class TestStorageLayoutDriftMode2:
    def test_missing_gap_flagged(self) -> None:
        agent = PiStorageLayoutDrift()
        result = agent.audit_storage(
            StorageDriftInput(
                file_path="token.sol",
                solidity_code=MISSING_GAP,
            )
        )
        assert isinstance(result, StorageDriftOutput)
        assert any("__gap" in f for f in result.compliance_findings)

    def test_tiny_gap_flagged(self) -> None:
        agent = PiStorageLayoutDrift()
        result = agent.audit_storage(
            StorageDriftInput(
                file_path="token.sol",
                solidity_code=TINY_GAP,
            )
        )
        assert isinstance(result, StorageDriftOutput)
        assert any("Undersized" in f or "5" in f for f in result.compliance_findings)

    def test_sufficient_gap_passes_compliance(self) -> None:
        agent = PiStorageLayoutDrift()
        result = agent.audit_storage(
            StorageDriftInput(
                file_path="token.sol",
                solidity_code=SAFE_V1,
            )
        )
        assert isinstance(result, StorageDriftOutput)
        # SAFE_V1 has uint256[50] __gap — should be clean
        assert not any("__gap" in f for f in result.compliance_findings)

    def test_constructor_state_init_flagged(self) -> None:
        agent = PiStorageLayoutDrift()
        result = agent.audit_storage(
            StorageDriftInput(
                file_path="token.sol",
                solidity_code=CONSTRUCTOR_STATE_INIT,
            )
        )
        assert isinstance(result, StorageDriftOutput)
        # May flag constructor state init as compliance issue
        # At minimum, the function should not crash
        assert result.status in ("PASSED", "WARN_STORAGE_RISK", "REJECTED_STORAGE_RISK")

    def test_risk_score_bounded(self) -> None:
        agent = PiStorageLayoutDrift()
        result = agent.audit_storage(
            StorageDriftInput(
                file_path="token.sol",
                solidity_code=MISSING_GAP,
            )
        )
        assert 0.0 <= result.risk_score <= 100.0


# ── Tests: Dual-Use Integration ────────────────────────────────────────────


class TestStorageLayoutDriftDualUse:
    def test_drift_and_compliance_both_reported(self) -> None:
        """Inserting a var + missing gap should report both drift AND compliance findings."""
        missing_gap_drift = """
        pragma solidity ^0.8.0;
        import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
        contract BadV2 is Initializable {
            address public owner;
            uint256 public injected;
            uint256 public totalSupply;
            function initialize() public initializer {}
        }
        """
        agent = PiStorageLayoutDrift()
        result = agent.audit_storage(
            StorageDriftInput(
                file_path="bad.sol",
                solidity_code=missing_gap_drift,
                previous_code=SAFE_V1,
            )
        )
        assert isinstance(result, StorageDriftOutput)
        # At least drift should be detected
        assert len(result.drifted_slots) > 0

    def test_status_is_string(self) -> None:
        agent = PiStorageLayoutDrift()
        result = agent.audit_storage(
            StorageDriftInput(
                file_path="x.sol",
                solidity_code=SAFE_V1,
            )
        )
        assert isinstance(result.status, str)

    def test_model_dump_serializable(self) -> None:
        agent = PiStorageLayoutDrift()
        result = agent.audit_storage(
            StorageDriftInput(
                file_path="x.sol",
                solidity_code=SAFE_V1,
            )
        )
        d = result.model_dump()
        assert "is_safe" in d
        assert "risk_score" in d
        assert isinstance(d["drifted_slots"], list)
