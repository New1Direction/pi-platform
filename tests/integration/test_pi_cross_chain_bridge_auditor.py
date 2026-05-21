"""Integration tests for PiCrossChainBridgeAuditor — bridge security & message integrity agent."""

import pytest

from pi_micro_agents.pi_cross_chain_bridge_auditor import (
    BridgeAuditInput,
    BridgeAuditOutput,
    PiCrossChainBridgeAuditor,
)

# ── Fixtures ───────────────────────────────────────────────────────────────

SECURE_BRIDGE = """
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/TimelockController.sol";

contract SecureBridge {
    mapping(bytes32 => bool) public processedNonces;
    address[] public validators;
    uint256 public quorum;

    event MessageSent(uint256 indexed dstChainId, address indexed sender, bytes payload);
    event MessageReceived(bytes32 indexed msgHash);

    // Fees tracked separately
    uint256 private _fees;

    function sendMessage(uint256 dstChainId, bytes calldata payload) external payable {
        _fees += msg.value;
        bytes32 msgHash = keccak256(abi.encode(block.chainid, dstChainId, msg.sender, payload));
        emit MessageSent(dstChainId, msg.sender, payload);
    }

    function executeMessage(
        uint256 srcChainId,
        address sender,
        bytes calldata payload,
        bytes[] calldata signatures
    ) external {
        // Verify quorum of validators have signed
        bytes32 msgHash = keccak256(abi.encode(block.chainid, srcChainId, sender, payload));
        require(!processedNonces[msgHash], "already executed");
        require(signatures.length >= quorum, "insufficient signatures");

        // Verify each signature against validator set
        uint256 validCount = 0;
        for (uint i = 0; i < signatures.length; i++) {
            address signer = _recoverSigner(msgHash, signatures[i]);
            if (_isValidator(signer)) validCount++;
        }
        require(validCount >= quorum, "quorum not reached");

        processedNonces[msgHash] = true;
        emit MessageReceived(msgHash);
        // Execute payload...
    }

    function _recoverSigner(bytes32 hash, bytes calldata sig) internal pure returns (address) { return address(0); }
    function _isValidator(address v) internal view returns (bool) { return true; }

    function setValidator(address v, bool active) external {
        // Controlled by TimelockController — 2-day delay enforced externally
        require(msg.sender == address(timelock), "only timelock");
    }
    TimelockController public timelock;
}
"""

UNVERIFIED_BRIDGE = """
pragma solidity ^0.8.0;

contract VulnerableBridge {
    event MessageSent(uint256 dstChainId, bytes payload);

    function sendMessage(uint256 dstChainId, bytes calldata payload) external payable {
        emit MessageSent(dstChainId, payload);
    }

    // No signature verification — anyone can call with any message
    function executeMessage(bytes calldata payload) external {
        // Just execute whatever is sent — no auth check at all
        (bool ok, ) = address(this).call(payload);
        require(ok, "failed");
    }
}
"""

NO_NONCE_BRIDGE = """
pragma solidity ^0.8.0;

contract NoNonceBridge {
    address[] public validators;

    function executeMessage(
        bytes calldata payload,
        bytes[] calldata signatures
    ) external {
        // Checks signatures but no nonce — can replay forever
        require(signatures.length >= 2, "need 2 sigs");
        // Process the message...
        (bool ok, ) = address(this).call(payload);
        require(ok);
    }

    function sendMessage(uint256 dstChainId, bytes calldata payload) external {
        bytes32 msgHash = keccak256(abi.encode(dstChainId, payload)); // no chainid!
        emit MsgSent(dstChainId, payload);
    }
    event MsgSent(uint256 dstChainId, bytes payload);
}
"""

CENTRALIZED_BRIDGE = """
pragma solidity ^0.8.0;

contract CentralizedBridge {
    mapping(bytes32 => bool) public processedNonces;
    address public owner;
    address public validator;

    function executeMessage(bytes32 msgHash, bytes calldata payload) external {
        require(msg.sender == validator, "only validator");
        require(!processedNonces[msgHash], "replay");
        processedNonces[msgHash] = true;
    }

    // Single owner can swap the validator instantly — no timelock
    function setValidator(address newValidator) external {
        require(msg.sender == owner, "only owner");
        validator = newValidator;
    }

    function sendMessage(uint256 dstChainId, bytes calldata payload) external {
        bytes32 h = keccak256(abi.encode(block.chainid, dstChainId, payload));
        emit Sent(dstChainId, payload);
    }
    event Sent(uint256 dstChainId, bytes payload);
}
"""

NO_CHAIN_ID_BRIDGE = """
pragma solidity ^0.8.0;

contract NoChainIdBridge {
    mapping(bytes32 => bool) public processedNonces;
    uint256 public quorum = 3;

    function executeMessage(address sender, bytes calldata payload, bytes[] calldata signatures) external {
        // Hash does NOT include chainId — same message can be replayed on other chains
        bytes32 msgHash = keccak256(abi.encode(sender, payload));
        require(!processedNonces[msgHash], "replay");
        require(signatures.length >= quorum, "need quorum");
        processedNonces[msgHash] = true;
    }

    function sendMessage(uint256 dstChainId, bytes calldata payload) external {
        // Missing chainId in hash
        bytes32 h = keccak256(abi.encode(dstChainId, payload));
        emit Sent(dstChainId, payload);
    }
    event Sent(uint256 dstChainId, bytes payload);
}
"""


# ── Tests: Mode 1 — Attack Vector Detection ───────────────────────────────

class TestCrossChainBridgeAuditorMode1:

    def test_secure_bridge_passes(self) -> None:
        agent = PiCrossChainBridgeAuditor()
        result = agent.audit_bridge(BridgeAuditInput(
            file_path="bridge.sol",
            solidity_code=SECURE_BRIDGE,
        ))
        assert isinstance(result, BridgeAuditOutput)
        assert result.is_secure is True
        assert result.status == "PASSED"
        assert result.risk_score == 0.0

    def test_unverified_message_auth_detected(self) -> None:
        agent = PiCrossChainBridgeAuditor()
        result = agent.audit_bridge(BridgeAuditInput(
            file_path="bridge.sol",
            solidity_code=UNVERIFIED_BRIDGE,
        ))
        assert isinstance(result, BridgeAuditOutput)
        assert len(result.unverified_messages) > 0
        assert result.risk_score >= 60.0
        assert result.status in ("WARN_BRIDGE_RISK", "REJECTED_BRIDGE_RISK")

    def test_missing_nonce_replay_detected(self) -> None:
        agent = PiCrossChainBridgeAuditor()
        result = agent.audit_bridge(BridgeAuditInput(
            file_path="bridge.sol",
            solidity_code=NO_NONCE_BRIDGE,
        ))
        assert isinstance(result, BridgeAuditOutput)
        assert len(result.replay_risks) > 0

    def test_centralized_validator_detected(self) -> None:
        agent = PiCrossChainBridgeAuditor()
        result = agent.audit_bridge(BridgeAuditInput(
            file_path="bridge.sol",
            solidity_code=CENTRALIZED_BRIDGE,
        ))
        assert isinstance(result, BridgeAuditOutput)
        assert len(result.centralization_risks) > 0

    def test_missing_chain_id_detected(self) -> None:
        agent = PiCrossChainBridgeAuditor()
        result = agent.audit_bridge(BridgeAuditInput(
            file_path="bridge.sol",
            solidity_code=NO_CHAIN_ID_BRIDGE,
        ))
        assert isinstance(result, BridgeAuditOutput)
        assert len(result.chain_id_issues) > 0

    def test_output_is_pydantic_model(self) -> None:
        agent = PiCrossChainBridgeAuditor()
        result = agent.audit_bridge(BridgeAuditInput(
            file_path="b.sol",
            solidity_code=SECURE_BRIDGE,
        ))
        assert isinstance(result, BridgeAuditOutput)
        assert hasattr(result, "is_secure")
        assert hasattr(result, "unverified_messages")
        assert hasattr(result, "replay_risks")
        assert hasattr(result, "chain_id_issues")
        assert hasattr(result, "centralization_risks")
        assert hasattr(result, "compliance_findings")
        assert hasattr(result, "risk_score")
        assert hasattr(result, "status")


# ── Tests: Mode 2 — Interface Compliance ──────────────────────────────────

class TestCrossChainBridgeAuditorMode2:

    def test_risk_score_higher_for_more_findings(self) -> None:
        agent = PiCrossChainBridgeAuditor()
        secure = agent.audit_bridge(BridgeAuditInput(
            file_path="b.sol", solidity_code=SECURE_BRIDGE
        ))
        unverified = agent.audit_bridge(BridgeAuditInput(
            file_path="b.sol", solidity_code=UNVERIFIED_BRIDGE
        ))
        assert unverified.risk_score > secure.risk_score

    def test_risk_score_bounded(self) -> None:
        for code in [SECURE_BRIDGE, UNVERIFIED_BRIDGE, NO_NONCE_BRIDGE, CENTRALIZED_BRIDGE]:
            agent = PiCrossChainBridgeAuditor()
            result = agent.audit_bridge(BridgeAuditInput(file_path="b.sol", solidity_code=code))
            assert 0.0 <= result.risk_score <= 100.0

    def test_status_values_valid(self) -> None:
        valid = {"PASSED", "WARN_BRIDGE_RISK", "REJECTED_BRIDGE_RISK"}
        for code in [SECURE_BRIDGE, UNVERIFIED_BRIDGE, NO_NONCE_BRIDGE]:
            agent = PiCrossChainBridgeAuditor()
            result = agent.audit_bridge(BridgeAuditInput(file_path="b.sol", solidity_code=code))
            assert result.status in valid


# ── Tests: Dual-Use & Serialization ───────────────────────────────────────

class TestCrossChainBridgeAuditorDualUse:

    def test_model_dump_serializable(self) -> None:
        agent = PiCrossChainBridgeAuditor()
        result = agent.audit_bridge(BridgeAuditInput(
            file_path="b.sol",
            solidity_code=SECURE_BRIDGE,
        ))
        d = result.model_dump()
        assert "is_secure" in d
        assert "risk_score" in d
        assert isinstance(d["unverified_messages"], list)
        assert isinstance(d["replay_risks"], list)
        assert isinstance(d["chain_id_issues"], list)
        assert isinstance(d["centralization_risks"], list)

    def test_multi_vector_bridge_high_risk(self) -> None:
        """A bridge with unverified msgs + no nonce + no chain-id should score very high."""
        agent = PiCrossChainBridgeAuditor()
        result = agent.audit_bridge(BridgeAuditInput(
            file_path="b.sol",
            solidity_code=UNVERIFIED_BRIDGE,
        ))
        assert result.risk_score >= 60.0

    def test_empty_code_does_not_crash(self) -> None:
        agent = PiCrossChainBridgeAuditor()
        result = agent.audit_bridge(BridgeAuditInput(
            file_path="empty.sol",
            solidity_code="",
        ))
        assert isinstance(result, BridgeAuditOutput)
        assert result.status in {"PASSED", "WARN_BRIDGE_RISK", "REJECTED_BRIDGE_RISK"}
