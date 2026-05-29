from __future__ import annotations

import copy

# ──────────────────────────────────────────────────────────────────────────
#  Optional Rust agent acceleration (flag-gated, parity-verified, fail-safe).
#
#  When PI_USE_RUST_AGENTS is truthy AND a Rust port exists for the agent, the
#  CPU-bound scan runs in the Rust core (`pi_core`), which releases the GIL —
#  ~5x on this concurrent fabric (Python's GIL can't parallelize CPU work).
#  Output parity is proven byte-for-byte in rust/parity. ANY problem (flag off,
#  pi_core missing, agent not ported, serialization issue) falls back to the
#  Python agent, so this can never change results or break execution.
# ──────────────────────────────────────────────────────────────────────────
import functools as _functools
import json
import os
import threading
import time
from typing import Any, Dict, List, Tuple

# Import outputs for Pydantic reconstruction in consensus testing
from pi_micro_agents.pi_access_control_verifier import AccessControlOutput
from pi_micro_agents.pi_agent_tool_execution_guard import AgentToolGuardOutput
from pi_micro_agents.pi_api_owasp_scanner import APIOutput
from pi_micro_agents.pi_arbitrage_guard import ArbitrageOutput
from pi_micro_agents.pi_architecture_import_boundary_sentry import ImportBoundaryOutput
from pi_micro_agents.pi_arithmetic_auditor import ArithmeticOutput
from pi_micro_agents.pi_assembly_lethal_weapons import AssemblySafetyOutput
from pi_micro_agents.pi_ast_depth_guard import AstDepthOutput
from pi_micro_agents.pi_audit_log_tamper_detector import LogOutput
from pi_micro_agents.pi_automated_anonymizer import AnonymizerOutput
from pi_micro_agents.pi_automated_rotation_engine import RotationOutput
from pi_micro_agents.pi_backup_integrity_checker import BackupOutput
from pi_micro_agents.pi_block_timestamp_sentry import BlockTimestampOutput
from pi_micro_agents.pi_bytecode_decompiler import BytecodeDecompilerOutput

# Cohort 11 Outputs
from pi_micro_agents.pi_caveman_token_compressor import CavemanCompressorOutput
from pi_micro_agents.pi_centralization_sentry import CentralizationOutput
from pi_micro_agents.pi_certificate_rotation_watcher import CertOutput
from pi_micro_agents.pi_changelog_auditor import ChangelogOutput
from pi_micro_agents.pi_cloud_config_auditor import CloudConfigOutput
from pi_micro_agents.pi_code_signing_enforcer import SigningOutput

# Adopted Skills Agent Outputs
from pi_micro_agents.pi_constant_time_auditor import ConstantTimeOutput
from pi_micro_agents.pi_container_escape_detector import ContainerEscapeOutput
from pi_micro_agents.pi_cross_chain_bridge_auditor import BridgeAuditOutput
from pi_micro_agents.pi_data_flow_privacy_mapper import PrivacyMapperOutput
from pi_micro_agents.pi_data_retention_policy_enforcer import RetentionOutput
from pi_micro_agents.pi_dead_code_pruner import DeadCodeOutput
from pi_micro_agents.pi_defi_slippage_guard import DeFiSlippageOutput
from pi_micro_agents.pi_dependency_vuln_scanner import DependencyOutput
from pi_micro_agents.pi_depreciation_scanner import DepreciationOutput
from pi_micro_agents.pi_design_an_interface_validator import DesignAnInterfaceOutput
from pi_micro_agents.pi_dimensional_analysis_sentry import DimensionalAnalysisOutput
from pi_micro_agents.pi_docker_image_scanner import DockerImageOutput
from pi_micro_agents.pi_dos_gas_limits_sentry import DoSGasLimitsOutput
from pi_micro_agents.pi_encryption_compliance_checker import EncryptionOutput
from pi_micro_agents.pi_erc4626_vault_guard import VaultGuardOutput
from pi_micro_agents.pi_error_handling_catch_all_guard import ErrorCatchOutput
from pi_micro_agents.pi_external_contract_guard import ExternalContractGuardOutput
from pi_micro_agents.pi_firewall_rule_auditor import FirewallOutput
from pi_micro_agents.pi_flash_loan_defender import FlashLoanOutput
from pi_micro_agents.pi_floating_pragma_sentry import PragmaSentryOutput
from pi_micro_agents.pi_gas_guzzler_detector import GasGuzzlerOutput
from pi_micro_agents.pi_git_safety_guardrail import GitSafetyOutput
from pi_micro_agents.pi_git_sec_scanner import GitSecOutput
from pi_micro_agents.pi_grill_me_questionnaire import GrillMeOutput
from pi_micro_agents.pi_handoff_checkpoint_sentry import HandoffOutput
from pi_micro_agents.pi_hardcoded_secret_detector import HardcodedSecretOutput
from pi_micro_agents.pi_hot_path_allocation_auditor import HotPathAllocationOutput

# Phase 4 Outputs
from pi_micro_agents.pi_iac_scanner import IaCOutput
from pi_micro_agents.pi_kubernetes_security_auditor import K8sOutput
from pi_micro_agents.pi_llm_output_sanitizer import LLMOutputSanitizerOutput
from pi_micro_agents.pi_logic_gatekeeper import LogicGatekeeperOutput
from pi_micro_agents.pi_magic_number_scanner import MagicNumberOutput
from pi_micro_agents.pi_memory_zeroize_sentry import MemoryZeroizeOutput
from pi_micro_agents.pi_mempool_sentry import MempoolTxOutput
from pi_micro_agents.pi_misconfig_pattern_matcher import MisconfigOutput
from pi_micro_agents.pi_mock_data_tainting_sentry import MockDataTaintingOutput
from pi_micro_agents.pi_oracle_divergence_audit import OracleDivergenceOutput
from pi_micro_agents.pi_oracle_sentry import OracleSentryOutput
from pi_micro_agents.pi_phishing_shield import PhishingShieldOutput
from pi_micro_agents.pi_publisher_dispatch import PublisherOutput
from pi_micro_agents.pi_rbac_permission_mapper import RBACOutput
from pi_micro_agents.pi_read_only_reentrancy_sentry import ReadOnlyReentrancyOutput
from pi_micro_agents.pi_readme_validator import ReadmeOutput
from pi_micro_agents.pi_reentrancy_sentry import ReentrancyOutput
from pi_micro_agents.pi_request_refactor_plan_verifier import RequestRefactorOutput
from pi_micro_agents.pi_runtime_anomaly_sentry import AnomalyOutput
from pi_micro_agents.pi_sbom_validator import SBOMOutput
from pi_micro_agents.pi_secrets_manager_completeness_checker import VaultOutput
from pi_micro_agents.pi_self_destruct_hunter import SelfDestructHunterOutput
from pi_micro_agents.pi_self_healing_patch_agent import SelfHealingOutput
from pi_micro_agents.pi_semantic_commit_message_linter import CommitLinterOutput
from pi_micro_agents.pi_sensitive_data_scanner import SensitiveDataOutput
from pi_micro_agents.pi_sensitive_log_leak_sentry import LogLeakOutput
from pi_micro_agents.pi_shadowed_variable_detector import ShadowedVariableOutput
from pi_micro_agents.pi_storage_layout_drift import StorageDriftOutput
from pi_micro_agents.pi_structured_logging_enforcer import StructuredLoggingOutput
from pi_micro_agents.pi_supply_chain_integrity_checker import SupplyChainOutput
from pi_micro_agents.pi_tdd_assertion_coverage import TddAssertionOutput
from pi_micro_agents.pi_tdd_mocking_sanity_checker import TddMockingOutput
from pi_micro_agents.pi_tdd_test_file_verifier import TddTestFileOutput
from pi_micro_agents.pi_threat_model_generator import ThreatModelOutput
from pi_micro_agents.pi_to_issues_breakdown import ToIssuesOutput
from pi_micro_agents.pi_to_prd_validator import ToPrdOutput
from pi_micro_agents.pi_token_tax_detector import TokenTaxOutput
from pi_micro_agents.pi_triage_bug_labels import TriageOutput
from pi_micro_agents.pi_tx_origin_sentry import TxOriginOutput
from pi_micro_agents.pi_typescript_wizardry_check import TypeScriptWizardryOutput
from pi_micro_agents.pi_uncontrolled_recursion_sentry import RecursionOutput
from pi_micro_agents.pi_uninitialized_state_sentry import UninitializedOutput
from pi_micro_agents.pi_upgrade_defect_detector import UpgradeDefectOutput
from pi_micro_agents.pi_vyper_sec_scanner import VyperScannerOutput
from pi_micro_agents.pi_zero_trust_verifier import ZeroTrustOutput
from pi_micro_agents.pi_zoom_out_system_explainer import ZoomOutOutput

# Consensus breaker imports
from pi_semantic_radius.consensus_breaker import ModelResponse
from pi_semantic_radius.consensus_breaker import PiConsensusBreaker as BaseConsensusBreaker


def _rust_enabled() -> bool:
    return os.getenv("PI_USE_RUST_AGENTS", "").strip().lower() in ("1", "true", "yes", "on")


@_functools.lru_cache(maxsize=1)
def _rust_core():
    import pi_core  # built via maturin from rust/crates/pi-py

    return pi_core


@_functools.lru_cache(maxsize=1)
def _rust_agent_names() -> frozenset:
    try:
        return frozenset(_rust_core().list_agents())
    except Exception:
        return frozenset()


def _find_output_model(agent_class, result_keys):
    """The agent module's pydantic model whose field set matches the Rust output."""
    import sys as _sys

    from pydantic import BaseModel

    mod = _sys.modules.get(getattr(agent_class, "__module__", "") or "")
    if mod is None:
        return None
    want = set(result_keys)
    for v in vars(mod).values():
        if (
            isinstance(v, type)
            and issubclass(v, BaseModel)
            and v is not BaseModel
            and set(v.model_fields.keys()) == want
        ):
            return v
    return None


def _try_rust_agent(agent_name, agent_class, perturbed):
    """Return a reconstructed Output model from the Rust core, or None to fall
    back to the Python agent. Never raises (fail-closed to Python)."""
    if not _rust_enabled():
        return None
    try:
        if agent_name not in _rust_agent_names():
            return None
        result = json.loads(_rust_core().run_agent(agent_name, perturbed.model_dump_json()))
        model = _find_output_model(agent_class, result.keys())
        return model(**result) if model is not None else None
    except Exception:
        return None


class PiConsensusBreaker(BaseConsensusBreaker):
    # Class-level once-flag for the missing-weights warning. Guarded by a
    # class-level lock so concurrent constructor calls don't print the
    # warning multiple times (or — worse — miss it entirely).
    _warning_printed = False
    _warning_lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.use_needle = os.getenv("PI_LOCAL_NEEDLE_ENGINE", "true").lower() in ("true", "1", "yes")
        self.engine = None

        if not self.use_needle:
            return

        from pathlib import Path

        weights_path = Path(__file__).parent.parent.parent.parent / "needle-int4-26m.gguf"
        if not weights_path.exists():
            weights_path_alt = Path(__file__).parent.parent.parent / "needle-int4-26m.gguf"
            if weights_path_alt.exists():
                weights_path = weights_path_alt

        if not weights_path.exists():
            with PiConsensusBreaker._warning_lock:
                if not PiConsensusBreaker._warning_printed:
                    try:
                        from rich.console import Console

                        Console().print(
                            "⚠️  [yellow]Needle weights missing – consensus will use legacy cloud fallback[/yellow]",
                            style="yellow",
                        )
                    except Exception:
                        print("⚠️  Needle weights missing – consensus will use legacy cloud fallback")
                    PiConsensusBreaker._warning_printed = True
            self.use_needle = False
            return


def perturb_input(inp: Any, index: int) -> Any:
    """Helper to perturb input to ensure independence between the three consensus runs."""
    if not inp:
        return inp
    new_inp = copy.deepcopy(inp)
    if hasattr(new_inp, "pool_price_a"):
        if index == 1:
            new_inp.pool_price_a *= 1.0001
        elif index == 2:
            new_inp.pool_price_a *= 0.9999
    elif hasattr(new_inp, "gas_price_gwei"):
        if index == 1:
            new_inp.gas_price_gwei += 0.05
        elif index == 2:
            new_inp.gas_price_gwei -= 0.05
    elif hasattr(new_inp, "content") and isinstance(new_inp.content, str):
        if index == 1:
            new_inp.content += " "
        elif index == 2:
            new_inp.content = " " + new_inp.content
    elif hasattr(new_inp, "current_observed_price"):
        if index == 1:
            new_inp.current_observed_price *= 1.0001
        elif index == 2:
            new_inp.current_observed_price *= 0.9999
    elif hasattr(new_inp, "source_code") and isinstance(new_inp.source_code, str):
        if index == 1:
            new_inp.source_code += " "
        elif index == 2:
            new_inp.source_code = " " + new_inp.source_code
    elif hasattr(new_inp, "solidity_code") and isinstance(new_inp.solidity_code, str):
        if index == 1:
            new_inp.solidity_code += " "
        elif index == 2:
            new_inp.solidity_code = " " + new_inp.solidity_code
    elif hasattr(new_inp, "vyper_code") and isinstance(new_inp.vyper_code, str):
        if index == 1:
            new_inp.vyper_code += " "
        elif index == 2:
            new_inp.vyper_code = " " + new_inp.vyper_code
    elif hasattr(new_inp, "prices") and isinstance(new_inp.prices, list) and new_inp.prices:
        if index == 1:
            new_inp.prices[0] *= 1.0001
        elif index == 2:
            new_inp.prices[0] *= 0.9999
    elif hasattr(new_inp, "command_string") and isinstance(new_inp.command_string, str):
        if index == 1:
            new_inp.command_string += " "
        elif index == 2:
            new_inp.command_string = " " + new_inp.command_string

    # Cohort 11 explicit perturbations
    for attr in [
        "text_payload",
        "plan_content",
        "handoff_content",
        "prd_content",
        "spec_content",
        "log_content",
        "code_content",
        "interface_content",
        "test_code_content",
        "data_content",
        "readme_content",
        "changelog_content",
        "commit_message",
        "dockerfile_content",
        "config_content",
        "file_content",
        "target_identifier",
        "raw_output",
        "text_content",
        "raw_payload",
        "iac_content",
        "lockfile_content",
        "config_snippet",
        "sbom_content",
        "manifest_content",
        "schema_content",
        "k8s_content",
        "network_policy_content",
        "cert_content",
        "rules_content",
        "backup_config",
        "system_desc",
        "vault_config",
        "artifact_metadata",
        "policy_content",
        "metrics_content",
    ]:
        if hasattr(new_inp, attr) and isinstance(getattr(new_inp, attr), str):
            val = getattr(new_inp, attr)
            if index == 1:
                setattr(new_inp, attr, val + " ")
            elif index == 2:
                setattr(new_inp, attr, " " + val)

    return new_inp


def get_comparable_dict(output: Any) -> Dict[str, Any]:
    """Helper to convert agent output to comparable dict, stripping dynamic fields."""
    if hasattr(output, "model_dump"):
        d = output.model_dump()
    elif hasattr(output, "dict"):
        d = output.dict()
    else:
        d = dict(output)
    d.pop("published_timestamp", None)
    d.pop("ledger_receipt_hash", None)
    return d


def get_verdict(agent_name: str, d: Dict[str, Any]) -> Any:
    """Gets primary outcome parameter (verdict) to assess consensus agreement."""
    if agent_name == "PiArbitrageGuard":
        return d.get("should_execute")
    elif agent_name == "PiMempoolSentry":
        return d.get("is_admitted")
    elif agent_name in ["PiGitSecScanner", "PiPublisherDispatch", "PiOracleSentry"]:
        return d.get("success") if agent_name == "PiPublisherDispatch" else d.get("is_secure")
    elif agent_name == "PiSelfHealingPatchAgent":
        return d.get("patch_synthesized")
    elif agent_name == "PiReentrancySentry":
        return d.get("is_secure")
    elif agent_name == "PiAccessControlVerifier":
        return d.get("is_secure")
    elif agent_name == "PiFlashLoanDefender":
        return d.get("is_secure")
    elif agent_name == "PiArithmeticAuditor":
        return d.get("is_secure")
    elif agent_name == "PiDelegateCallGuard":
        return d.get("is_secure")
    elif agent_name == "PiSignatureReplayScout":
        return d.get("is_secure")
    elif agent_name == "PiStorageLayoutDrift":
        return d.get("is_safe")
    elif agent_name == "PiERC4626VaultGuard":
        return d.get("is_compliant")
    elif agent_name in [
        "PiBytecodeDecompiler",
        "PiVyperSecScanner",
        "PiSelfDestructHunter",
        "PiOracleDivergenceAudit",
        "PiTokenTaxDetector",
        "PiTxOriginSentry",
        "PiReadOnlyReentrancySentry",
        "PiUninitializedStateSentry",
        "PiShadowedVariableDetector",
        "PiBlockTimestampSentry",
        "PiCrossChainBridgeAuditor",
        "PiGasGuzzlerDetector",
        "PiAssemblyLethalWeapons",
        "PiLogicGatekeeper",
        "PiPhishingShield",
        "PiExternalContractGuard",
        "PiCentralizationSentry",
        "PiFloatingPragmaSentry",
        "PiUpgradeDefectDetector",
        "PiDoSGasLimitsSentry",
        "PiDeFiSlippageGuard",
        "PiConstantTimeAuditor",
        "PiMemoryZeroizeSentry",
        "PiDimensionalAnalysisSentry",
        "PiAgentToolExecutionGuard",
        "PiHotPathAllocationAuditor",
        "PiCavemanTokenCompressor",
        "PiGrillMeQuestionnaire",
        "PiHandoffCheckpointSentry",
        "PiToPrdValidator",
        "PiToIssuesBreakdown",
        "PiTriageBugLabels",
        "PiZoomOutSystemExplainer",
        "PiDesignAnInterfaceValidator",
        "PiRequestRefactorPlanVerifier",
        "PiTddTestFileVerifier",
        "PiTddAssertionCoverage",
        "PiTddMockingSanityChecker",
        "PiGitSafetyGuardrail",
        "PiTypeScriptWizardryCheck",
        "PiArchitectureImportBoundarySentry",
        "PiDepreciationScanner",
        "PiDeadCodePruner",
        "PiMockDataTaintingSentry",
        "PiReadmeValidator",
        "PiChangelogAuditor",
        "PiAstDepthGuard",
        "PiUncontrolledRecursionSentry",
        "PiMagicNumberScanner",
        "PiErrorHandlingCatchAllGuard",
        "PiSemanticCommitMessageLinter",
        "PiWebVulnScanner",
        "PiPipelineIntegrityAuditor",
        "PiDockerImageScanner",
        "PiContainerEscapeDetector",
        "PiHardcodedSecretDetector",
        "PiLLMOutputSanitizer",
        "PiDataFlowPrivacyMapper",
        "PiSensitiveDataScanner",
        "PiAutomatedAnonymizer",
        "PiSensitiveLogLeakSentry",
        "PiStructuredLoggingEnforcer",
        "PiIaCScanner",
        "PiDependencyVulnScanner",
        "PiCloudConfigAuditor",
        "PiRBACPermissionMapper",
        "PiEncryptionComplianceChecker",
        "PiSBOMValidator",
        "PiSupplyChainIntegrityChecker",
        "PiAPIOWASPScanner",
        "PiKubernetesSecurityAuditor",
        "PiZeroTrustVerifier",
        "PiCertificateRotationWatcher",
        "PiFirewallRuleAuditor",
        "PiBackupIntegrityChecker",
        "PiAuditLogTamperDetector",
        "PiMisconfigPatternMatcher",
        "PiThreatModelGenerator",
        "PiSecretsManagerCompletenessChecker",
        "PiCodeSigningEnforcer",
        "PiDataRetentionPolicyEnforcer",
        "PiRuntimeAnomalySentry",
    ]:
        return d.get("is_secure")
    elif agent_name == "PiDeploymentSafetyGuard":
        return d.get("deployment_allowed")
    elif agent_name == "PiAutomatedRotationEngine":
        return d.get("rotation_completed")

    return None


def run_with_consensus(
    orchestrator: Any, agent_class: Any, input_envelope: Any, goal: str, context: Dict[str, Any], agent_name: str
) -> Tuple[bool, float, str, Dict[str, Any], List[str]]:
    """Spins up three independent runs, audits outcomes via PiConsensusBreaker, and applies consensus gate."""
    mock_runs = context.get("mock_consensus_runs")
    outputs = []

    if mock_runs:
        # Parse mock runs into proper output classes
        for r in mock_runs:
            if agent_name == "PiArbitrageGuard":
                outputs.append(ArbitrageOutput(**r))
            elif agent_name == "PiMempoolSentry":
                outputs.append(MempoolTxOutput(**r))
            elif agent_name == "PiGitSecScanner":
                outputs.append(GitSecOutput(**r))
            elif agent_name == "PiPublisherDispatch":
                outputs.append(PublisherOutput(**r))
            elif agent_name == "PiOracleSentry":
                outputs.append(OracleSentryOutput(**r))
            elif agent_name == "PiSelfHealingPatchAgent":
                outputs.append(SelfHealingOutput(**r))
            elif agent_name == "PiReentrancySentry":
                outputs.append(ReentrancyOutput(**r))
            elif agent_name == "PiAccessControlVerifier":
                outputs.append(AccessControlOutput(**r))
            elif agent_name == "PiFlashLoanDefender":
                outputs.append(FlashLoanOutput(**r))
            elif agent_name == "PiArithmeticAuditor":
                outputs.append(ArithmeticOutput(**r))
            elif agent_name == "PiBytecodeDecompiler":
                outputs.append(BytecodeDecompilerOutput(**r))
            elif agent_name == "PiVyperSecScanner":
                outputs.append(VyperScannerOutput(**r))
            elif agent_name == "PiSelfDestructHunter":
                outputs.append(SelfDestructHunterOutput(**r))
            elif agent_name == "PiOracleDivergenceAudit":
                outputs.append(OracleDivergenceOutput(**r))
            elif agent_name == "PiTokenTaxDetector":
                outputs.append(TokenTaxOutput(**r))
            elif agent_name == "PiTxOriginSentry":
                outputs.append(TxOriginOutput(**r))
            elif agent_name == "PiReadOnlyReentrancySentry":
                outputs.append(ReadOnlyReentrancyOutput(**r))
            elif agent_name == "PiUninitializedStateSentry":
                outputs.append(UninitializedOutput(**r))
            elif agent_name == "PiShadowedVariableDetector":
                outputs.append(ShadowedVariableOutput(**r))
            elif agent_name == "PiBlockTimestampSentry":
                outputs.append(BlockTimestampOutput(**r))
            elif agent_name == "PiStorageLayoutDrift":
                outputs.append(StorageDriftOutput(**r))
            elif agent_name == "PiERC4626VaultGuard":
                outputs.append(VaultGuardOutput(**r))
            elif agent_name == "PiCrossChainBridgeAuditor":
                outputs.append(BridgeAuditOutput(**r))
            elif agent_name == "PiGasGuzzlerDetector":
                outputs.append(GasGuzzlerOutput(**r))
            elif agent_name == "PiAssemblyLethalWeapons":
                outputs.append(AssemblySafetyOutput(**r))
            elif agent_name == "PiLogicGatekeeper":
                outputs.append(LogicGatekeeperOutput(**r))
            elif agent_name == "PiPhishingShield":
                outputs.append(PhishingShieldOutput(**r))
            elif agent_name == "PiExternalContractGuard":
                outputs.append(ExternalContractGuardOutput(**r))
            elif agent_name == "PiCentralizationSentry":
                outputs.append(CentralizationOutput(**r))
            elif agent_name == "PiFloatingPragmaSentry":
                outputs.append(PragmaSentryOutput(**r))
            elif agent_name == "PiUpgradeDefectDetector":
                outputs.append(UpgradeDefectOutput(**r))
            elif agent_name == "PiDoSGasLimitsSentry":
                outputs.append(DoSGasLimitsOutput(**r))
            elif agent_name == "PiDeFiSlippageGuard":
                outputs.append(DeFiSlippageOutput(**r))
            elif agent_name == "PiConstantTimeAuditor":
                outputs.append(ConstantTimeOutput(**r))
            elif agent_name == "PiMemoryZeroizeSentry":
                outputs.append(MemoryZeroizeOutput(**r))
            elif agent_name == "PiDimensionalAnalysisSentry":
                outputs.append(DimensionalAnalysisOutput(**r))
            elif agent_name == "PiAgentToolExecutionGuard":
                outputs.append(AgentToolGuardOutput(**r))
            elif agent_name == "PiHotPathAllocationAuditor":
                outputs.append(HotPathAllocationOutput(**r))
            elif agent_name == "PiCavemanTokenCompressor":
                outputs.append(CavemanCompressorOutput(**r))
            elif agent_name == "PiGrillMeQuestionnaire":
                outputs.append(GrillMeOutput(**r))
            elif agent_name == "PiHandoffCheckpointSentry":
                outputs.append(HandoffOutput(**r))
            elif agent_name == "PiToPrdValidator":
                outputs.append(ToPrdOutput(**r))
            elif agent_name == "PiToIssuesBreakdown":
                outputs.append(ToIssuesOutput(**r))
            elif agent_name == "PiTriageBugLabels":
                outputs.append(TriageOutput(**r))
            elif agent_name == "PiZoomOutSystemExplainer":
                outputs.append(ZoomOutOutput(**r))
            elif agent_name == "PiDesignAnInterfaceValidator":
                outputs.append(DesignAnInterfaceOutput(**r))
            elif agent_name == "PiRequestRefactorPlanVerifier":
                outputs.append(RequestRefactorOutput(**r))
            elif agent_name == "PiTddTestFileVerifier":
                outputs.append(TddTestFileOutput(**r))
            elif agent_name == "PiTddAssertionCoverage":
                outputs.append(TddAssertionOutput(**r))
            elif agent_name == "PiTddMockingSanityChecker":
                outputs.append(TddMockingOutput(**r))
            elif agent_name == "PiGitSafetyGuardrail":
                outputs.append(GitSafetyOutput(**r))
            elif agent_name == "PiTypeScriptWizardryCheck":
                outputs.append(TypeScriptWizardryOutput(**r))
            elif agent_name == "PiArchitectureImportBoundarySentry":
                outputs.append(ImportBoundaryOutput(**r))
            elif agent_name == "PiDepreciationScanner":
                outputs.append(DepreciationOutput(**r))
            elif agent_name == "PiDeadCodePruner":
                outputs.append(DeadCodeOutput(**r))
            elif agent_name == "PiMockDataTaintingSentry":
                outputs.append(MockDataTaintingOutput(**r))
            elif agent_name == "PiReadmeValidator":
                outputs.append(ReadmeOutput(**r))
            elif agent_name == "PiChangelogAuditor":
                outputs.append(ChangelogOutput(**r))
            elif agent_name == "PiAstDepthGuard":
                outputs.append(AstDepthOutput(**r))
            elif agent_name == "PiUncontrolledRecursionSentry":
                outputs.append(RecursionOutput(**r))
            elif agent_name == "PiMagicNumberScanner":
                outputs.append(MagicNumberOutput(**r))
            elif agent_name == "PiErrorHandlingCatchAllGuard":
                outputs.append(ErrorCatchOutput(**r))
            elif agent_name == "PiSemanticCommitMessageLinter":
                outputs.append(CommitLinterOutput(**r))
            elif agent_name == "PiDockerImageScanner":
                outputs.append(DockerImageOutput(**r))
            elif agent_name == "PiContainerEscapeDetector":
                outputs.append(ContainerEscapeOutput(**r))
            elif agent_name == "PiHardcodedSecretDetector":
                outputs.append(HardcodedSecretOutput(**r))
            elif agent_name == "PiAutomatedRotationEngine":
                outputs.append(RotationOutput(**r))
            elif agent_name == "PiLLMOutputSanitizer":
                outputs.append(LLMOutputSanitizerOutput(**r))
            elif agent_name == "PiDataFlowPrivacyMapper":
                outputs.append(PrivacyMapperOutput(**r))
            elif agent_name == "PiSensitiveDataScanner":
                outputs.append(SensitiveDataOutput(**r))
            elif agent_name == "PiAutomatedAnonymizer":
                outputs.append(AnonymizerOutput(**r))
            elif agent_name == "PiSensitiveLogLeakSentry":
                outputs.append(LogLeakOutput(**r))
            elif agent_name == "PiStructuredLoggingEnforcer":
                outputs.append(StructuredLoggingOutput(**r))
            elif agent_name == "PiIaCScanner":
                outputs.append(IaCOutput(**r))
            elif agent_name == "PiDependencyVulnScanner":
                outputs.append(DependencyOutput(**r))
            elif agent_name == "PiCloudConfigAuditor":
                outputs.append(CloudConfigOutput(**r))
            elif agent_name == "PiRBACPermissionMapper":
                outputs.append(RBACOutput(**r))
            elif agent_name == "PiEncryptionComplianceChecker":
                outputs.append(EncryptionOutput(**r))
            elif agent_name == "PiSBOMValidator":
                outputs.append(SBOMOutput(**r))
            elif agent_name == "PiSupplyChainIntegrityChecker":
                outputs.append(SupplyChainOutput(**r))
            elif agent_name == "PiAPIOWASPScanner":
                outputs.append(APIOutput(**r))
            elif agent_name == "PiKubernetesSecurityAuditor":
                outputs.append(K8sOutput(**r))
            elif agent_name == "PiZeroTrustVerifier":
                outputs.append(ZeroTrustOutput(**r))
            elif agent_name == "PiCertificateRotationWatcher":
                outputs.append(CertOutput(**r))
            elif agent_name == "PiFirewallRuleAuditor":
                outputs.append(FirewallOutput(**r))
            elif agent_name == "PiBackupIntegrityChecker":
                outputs.append(BackupOutput(**r))
            elif agent_name == "PiAuditLogTamperDetector":
                outputs.append(LogOutput(**r))
            elif agent_name == "PiMisconfigPatternMatcher":
                outputs.append(MisconfigOutput(**r))
            elif agent_name == "PiThreatModelGenerator":
                outputs.append(ThreatModelOutput(**r))
            elif agent_name == "PiSecretsManagerCompletenessChecker":
                outputs.append(VaultOutput(**r))
            elif agent_name == "PiCodeSigningEnforcer":
                outputs.append(SigningOutput(**r))
            elif agent_name == "PiDataRetentionPolicyEnforcer":
                outputs.append(RetentionOutput(**r))
            elif agent_name == "PiRuntimeAnomalySentry":
                outputs.append(AnomalyOutput(**r))
            else:
                outputs.append(r)

    else:
        # Execute 3 independent perturbed runs (parallel via ThreadPoolExecutor when Needle enabled)
        def run_single_perturbed(idx):
            agent_inst = (
                agent_class(ledger=orchestrator.ledger) if agent_name == "PiPublisherDispatch" else agent_class()
            )
            perturbed = perturb_input(input_envelope, idx)
            # Flag-gated Rust acceleration (parity-verified, falls back to Python on any issue).
            _rust_out = _try_rust_agent(agent_name, agent_class, perturbed)
            if _rust_out is not None:
                return _rust_out
            if agent_name == "PiArbitrageGuard":
                return agent_inst.analyze_spread(perturbed)
            elif agent_name == "PiMempoolSentry":
                return agent_inst.check_transaction(perturbed)
            elif agent_name == "PiGitSecScanner":
                return agent_inst.scan_file(perturbed)
            elif agent_name == "PiPublisherDispatch":
                return agent_inst.dispatch_publications(perturbed)
            elif agent_name == "PiOracleSentry":
                return agent_inst.audit_prices(perturbed)
            elif agent_name == "PiSelfHealingPatchAgent":
                return agent_inst.heal_vulnerabilities(perturbed)
            elif agent_name == "PiReentrancySentry":
                return agent_inst.audit_reentrancy(perturbed)
            elif agent_name == "PiAccessControlVerifier":
                return agent_inst.audit_access_control(perturbed)
            elif agent_name == "PiFlashLoanDefender":
                return agent_inst.audit_flash_loan(perturbed)
            elif agent_name == "PiArithmeticAuditor":
                return agent_inst.audit_arithmetic(perturbed)
            elif agent_name == "PiDelegateCallGuard":
                return agent_inst.audit_delegatecall(perturbed)
            elif agent_name == "PiSignatureReplayScout":
                return agent_inst.audit_signature(perturbed)
            elif agent_name == "PiBytecodeDecompiler":
                return agent_inst.audit_bytecode(perturbed)
            elif agent_name == "PiVyperSecScanner":
                return agent_inst.audit_vyper(perturbed)
            elif agent_name == "PiSelfDestructHunter":
                return agent_inst.audit_selfdestruct(perturbed)
            elif agent_name == "PiOracleDivergenceAudit":
                return agent_inst.audit_divergence(perturbed)
            elif agent_name == "PiTokenTaxDetector":
                return agent_inst.audit_token_tax(perturbed)
            elif agent_name == "PiTxOriginSentry":
                return agent_inst.audit_tx_origin(perturbed)
            elif agent_name == "PiReadOnlyReentrancySentry":
                return agent_inst.audit_readonly_reentrancy(perturbed)
            elif agent_name == "PiUninitializedStateSentry":
                return agent_inst.audit_uninitialized(perturbed)
            elif agent_name == "PiShadowedVariableDetector":
                return agent_inst.audit_shadowed(perturbed)
            elif agent_name == "PiBlockTimestampSentry":
                return agent_inst.audit_timestamp(perturbed)
            elif agent_name == "PiStorageLayoutDrift":
                return agent_inst.audit_storage(perturbed)
            elif agent_name == "PiERC4626VaultGuard":
                return agent_inst.audit_vault(perturbed)
            elif agent_name == "PiCrossChainBridgeAuditor":
                return agent_inst.audit_bridge(perturbed)
            elif agent_name == "PiGasGuzzlerDetector":
                return agent_inst.audit_gas(perturbed)
            elif agent_name == "PiAssemblyLethalWeapons":
                return agent_inst.audit_assembly(perturbed)
            elif agent_name == "PiLogicGatekeeper":
                return agent_inst.audit_logic(perturbed)
            elif agent_name == "PiPhishingShield":
                return agent_inst.audit_phishing(perturbed)
            elif agent_name == "PiExternalContractGuard":
                return agent_inst.audit_external(perturbed)
            elif agent_name == "PiCentralizationSentry":
                return agent_inst.audit_centralization(perturbed)
            elif agent_name == "PiFloatingPragmaSentry":
                return agent_inst.audit_pragma(perturbed)
            elif agent_name == "PiUpgradeDefectDetector":
                return agent_inst.audit_upgrade(perturbed)
            elif agent_name == "PiDoSGasLimitsSentry":
                return agent_inst.audit_dos_gas(perturbed)
            elif agent_name == "PiDeFiSlippageGuard":
                return agent_inst.audit_slippage(perturbed)
            elif agent_name == "PiConstantTimeAuditor":
                return agent_inst.audit_constant_time(perturbed)
            elif agent_name == "PiMemoryZeroizeSentry":
                return agent_inst.audit_memory_zeroize(perturbed)
            elif agent_name == "PiDimensionalAnalysisSentry":
                return agent_inst.audit_dimensions(perturbed)
            elif agent_name == "PiAgentToolExecutionGuard":
                return agent_inst.audit_agent_command(perturbed)
            elif agent_name == "PiHotPathAllocationAuditor":
                return agent_inst.audit_hot_path(perturbed)
            elif agent_name == "PiCavemanTokenCompressor":
                return agent_inst.compress_tokens(perturbed)
            elif agent_name == "PiGrillMeQuestionnaire":
                return agent_inst.grill_plan(perturbed)
            elif agent_name == "PiHandoffCheckpointSentry":
                return agent_inst.audit_handoff(perturbed)
            elif agent_name == "PiToPrdValidator":
                return agent_inst.validate_prd(perturbed)
            elif agent_name == "PiToIssuesBreakdown":
                return agent_inst.breakdown_issues(perturbed)
            elif agent_name == "PiTriageBugLabels":
                return agent_inst.triage_bug(perturbed)
            elif agent_name == "PiZoomOutSystemExplainer":
                return agent_inst.explain_system(perturbed)
            elif agent_name == "PiDesignAnInterfaceValidator":
                return agent_inst.validate_interface(perturbed)
            elif agent_name == "PiRequestRefactorPlanVerifier":
                return agent_inst.verify_refactor(perturbed)
            elif agent_name == "PiTddTestFileVerifier":
                return agent_inst.verify_test_files(perturbed)
            elif agent_name == "PiTddAssertionCoverage":
                return agent_inst.check_assertion_coverage(perturbed)
            elif agent_name == "PiTddMockingSanityChecker":
                return agent_inst.check_mocking_sanity(perturbed)
            elif agent_name == "PiGitSafetyGuardrail":
                return agent_inst.check_git_safety(perturbed)
            elif agent_name == "PiTypeScriptWizardryCheck":
                return agent_inst.check_typescript(perturbed)
            elif agent_name == "PiArchitectureImportBoundarySentry":
                return agent_inst.check_import_boundaries(perturbed)
            elif agent_name == "PiDepreciationScanner":
                return agent_inst.scan_depreciation(perturbed)
            elif agent_name == "PiDeadCodePruner":
                return agent_inst.prune_dead_code(perturbed)
            elif agent_name == "PiMockDataTaintingSentry":
                return agent_inst.check_mock_tainting(perturbed)
            elif agent_name == "PiReadmeValidator":
                return agent_inst.validate_readme(perturbed)
            elif agent_name == "PiChangelogAuditor":
                return agent_inst.audit_changelog(perturbed)
            elif agent_name == "PiAstDepthGuard":
                return agent_inst.check_ast_depth(perturbed)
            elif agent_name == "PiUncontrolledRecursionSentry":
                return agent_inst.check_recursion(perturbed)
            elif agent_name == "PiMagicNumberScanner":
                return agent_inst.scan_magic_numbers(perturbed)
            elif agent_name == "PiErrorHandlingCatchAllGuard":
                return agent_inst.check_error_handling(perturbed)
            elif agent_name == "PiSemanticCommitMessageLinter":
                return agent_inst.audit_commit_message(perturbed)
            elif agent_name == "PiDockerImageScanner":
                return agent_inst.scan_docker_image(perturbed)
            elif agent_name == "PiContainerEscapeDetector":
                return agent_inst.scan_container_escape(perturbed)
            elif agent_name == "PiHardcodedSecretDetector":
                return agent_inst.scan_hardcoded_secrets(perturbed)
            elif agent_name == "PiAutomatedRotationEngine":
                return agent_inst.rotate_credential(perturbed)
            elif agent_name == "PiLLMOutputSanitizer":
                return agent_inst.sanitize_llm_output(perturbed)
            elif agent_name == "PiDataFlowPrivacyMapper":
                return agent_inst.map_data_privacy_flows(perturbed)
            elif agent_name == "PiSensitiveDataScanner":
                return agent_inst.scan_sensitive_data(perturbed)
            elif agent_name == "PiAutomatedAnonymizer":
                return agent_inst.anonymize_payload(perturbed)
            elif agent_name == "PiSensitiveLogLeakSentry":
                return agent_inst.audit_log_leaks(perturbed)
            elif agent_name == "PiStructuredLoggingEnforcer":
                return agent_inst.enforce_structured_logging(perturbed)
            elif agent_name == "PiIaCScanner":
                return agent_inst.scan_iac(perturbed)
            elif agent_name == "PiDependencyVulnScanner":
                return agent_inst.scan_dependencies(perturbed)
            elif agent_name == "PiCloudConfigAuditor":
                return agent_inst.audit_config(perturbed)
            elif agent_name == "PiRBACPermissionMapper":
                return agent_inst.map_rbac_permissions(perturbed)
            elif agent_name == "PiEncryptionComplianceChecker":
                return agent_inst.check_encryption_compliance(perturbed)
            elif agent_name == "PiSBOMValidator":
                return agent_inst.validate_sbom(perturbed)
            elif agent_name == "PiSupplyChainIntegrityChecker":
                return agent_inst.check_supply_chain(perturbed)
            elif agent_name == "PiAPIOWASPScanner":
                return agent_inst.scan_api(perturbed)
            elif agent_name == "PiKubernetesSecurityAuditor":
                return agent_inst.audit_k8s(perturbed)
            elif agent_name == "PiZeroTrustVerifier":
                return agent_inst.verify_zero_trust(perturbed)
            elif agent_name == "PiCertificateRotationWatcher":
                return agent_inst.watch_certificate(perturbed)
            elif agent_name == "PiFirewallRuleAuditor":
                return agent_inst.audit_firewall(perturbed)
            elif agent_name == "PiBackupIntegrityChecker":
                return agent_inst.check_backup(perturbed)
            elif agent_name == "PiAuditLogTamperDetector":
                return agent_inst.detect_tampering(perturbed)
            elif agent_name == "PiMisconfigPatternMatcher":
                return agent_inst.match_config(perturbed)
            elif agent_name == "PiThreatModelGenerator":
                return agent_inst.generate_threat_model(perturbed)
            elif agent_name == "PiSecretsManagerCompletenessChecker":
                return agent_inst.check_vault_config(perturbed)
            elif agent_name == "PiCodeSigningEnforcer":
                return agent_inst.verify_signing(perturbed)
            elif agent_name == "PiDataRetentionPolicyEnforcer":
                return agent_inst.enforce_retention(perturbed)
            elif agent_name == "PiRuntimeAnomalySentry":
                return agent_inst.audit_runtime(perturbed)
            raise ValueError(f"Unknown agent: {agent_name}")

        from pathlib import Path

        weights_path = Path(__file__).parent.parent.parent.parent / "needle-int4-26m.gguf"
        if not weights_path.exists():
            weights_path_alt = Path(__file__).parent.parent.parent / "needle-int4-26m.gguf"
            if weights_path_alt.exists():
                weights_path = weights_path_alt

        use_needle = (
            os.getenv("PI_LOCAL_NEEDLE_ENGINE", "true").lower() in ("true", "1", "yes") and weights_path.exists()
        )
        if use_needle:
            import concurrent.futures

            _timeout = int(os.getenv("PI_CONSENSUS_TIMEOUT_SECONDS", "30"))
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(run_single_perturbed, idx) for idx in range(3)]
                outputs = [f.result(timeout=_timeout) for f in futures]
        else:
            for idx in range(3):
                outputs.append(run_single_perturbed(idx))

    # Evaluate consensus via PiConsensusBreaker
    responses = []
    for i, out in enumerate(outputs):
        content = (
            out.model_dump_json()
            if hasattr(out, "model_dump_json")
            else (out.json() if hasattr(out, "json") else json.dumps(out))
        )
        responses.append(
            ModelResponse(model_name=f"Agent Run {i + 1}", content=content, parsed_json=get_comparable_dict(out))
        )

    breaker = PiConsensusBreaker(divergence_threshold=60.0)
    report = breaker.evaluate_consensus(goal, responses)

    d1 = get_comparable_dict(outputs[0])
    d2 = get_comparable_dict(outputs[1])
    d3 = get_comparable_dict(outputs[2])

    v1 = get_verdict(agent_name, d1)
    v2 = get_verdict(agent_name, d2)
    v3 = get_verdict(agent_name, d3)

    consensus_achieved = False
    majority_idx = 0

    # Treat None verdicts as unresolvable — two None values must not count as agreement
    if v1 is not None and v1 == v2:
        consensus_achieved = True
        majority_idx = 0
    elif v1 is not None and v1 == v3:
        consensus_achieved = True
        majority_idx = 0
    elif v2 is not None and v2 == v3:
        consensus_achieved = True
        majority_idx = 1

    _ts = time.time()
    votes = [
        {
            "agent_name": "Agent Run 1",
            "verdict": str(v1),
            "params": str(d1),
            "recorded_at": _ts,
            "risk_score": d1.get("risk_score", 0.0),
        },
        {
            "agent_name": "Agent Run 2",
            "verdict": str(v2),
            "params": str(d2),
            "recorded_at": _ts,
            "risk_score": d2.get("risk_score", 0.0),
        },
        {
            "agent_name": "Agent Run 3",
            "verdict": str(v3),
            "params": str(d3),
            "recorded_at": _ts,
            "risk_score": d3.get("risk_score", 0.0),
        },
    ]

    success = False
    risk_score = report.consensus_divergence_score
    summary = ""
    result_details = {}
    anomalies = []

    if report.is_broken or not consensus_achieved:
        success = False
        summary = (
            f"Blocked: Multi-agent consensus coordination alarm! "
            f"Consensus Divergence Score: {report.consensus_divergence_score:.2f}% (Threshold: 60.0%). "
            f"Verdicts: Agent 1 = {v1}, Agent 2 = {v2}, Agent 3 = {v3}."
        )
        anomalies.append("Consensus violation: Divergence or split vote detected.")
        result_details = {
            "consensus_telemetry": {
                "status": "REJECTED_DIVERGENCE_ALARM",
                "divergence_score": report.consensus_divergence_score,
                "votes": votes,
            }
        }
    else:
        majority_verdict = v1 if majority_idx == 0 else v2
        success = bool(majority_verdict) if majority_verdict is not None else False
        majority_out = outputs[majority_idx]
        majority_dict = get_comparable_dict(majority_out)

        risk_score = 0.0
        alerts = []
        if agent_name == "PiArbitrageGuard":
            if "BLOCKED" in majority_dict.get("route_details", ""):
                alerts.append("High risk spread anomaly or oracle manipulation detected.")
                success = False
                risk_score = 90.0
            summary = f"Arbitrage calculation complete (Consensus Passed). Route: {majority_dict.get('route_details')}. Profit: {majority_dict.get('expected_profit', 0.0):.4f}"
        elif agent_name == "PiMempoolSentry":
            alerts.extend(majority_dict.get("alerts", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Mempool audit finished (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiGitSecScanner":
            alerts.extend(majority_dict.get("flagged_vulnerabilities", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static security scan on {input_envelope.filename} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiPublisherDispatch":
            alerts.extend(majority_dict.get("anomalies_detected", []))
            summary = f"Curation publication dispatched (Consensus Passed). Substack URL: {majority_dict.get('substack_post_url')}"
            if alerts:
                risk_score = 95.0
        elif agent_name == "PiOracleSentry":
            alerts.extend(majority_dict.get("flagged_anomalies", []))
            risk_score = 90.0 if not majority_dict.get("is_secure") else 0.0
            summary = f"Oracle security audit completed (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiSelfHealingPatchAgent":
            alerts.extend(majority_dict.get("remediations", []))
            risk_score = 60.0 if not majority_dict.get("patch_synthesized") else 0.0
            summary = (
                f"Autonomous self-healing repair complete (Consensus Passed). Status: {majority_dict.get('status')}"
            )
        elif agent_name == "PiReentrancySentry":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity reentrancy scan on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiAccessControlVerifier":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity access control scan on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiFlashLoanDefender":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity flash loan audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiArithmeticAuditor":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity arithmetic audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiDelegateCallGuard":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity delegatecall audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiSignatureReplayScout":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity signature replay audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiBytecodeDecompiler":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed EVM bytecode and assembly audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiVyperSecScanner":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Vyper security scan on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiSelfDestructHunter":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity selfdestruct scan on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiOracleDivergenceAudit":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity oracle price divergence audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiTokenTaxDetector":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity token tax audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiTxOriginSentry":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity tx.origin authorization scan on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiReadOnlyReentrancySentry":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity read-only reentrancy scan on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiUninitializedStateSentry":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity uninitialized storage scan on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiShadowedVariableDetector":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity shadowed variable audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiBlockTimestampSentry":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static Solidity block timestamp reliance audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiStorageLayoutDrift":
            alerts.extend(majority_dict.get("drifted_slots", []))
            alerts.extend(majority_dict.get("compliance_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed storage layout drift audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiERC4626VaultGuard":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed ERC-4626 vault audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiCrossChainBridgeAuditor":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed cross-chain bridge audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiGasGuzzlerDetector":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed gas guzzler audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiAssemblyLethalWeapons":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed inline assembly safety audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiLogicGatekeeper":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed logic gatekeeper audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiPhishingShield":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed phishing shield audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiExternalContractGuard":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed external contract guard audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiCentralizationSentry":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed centralization risk audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiFloatingPragmaSentry":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed floating pragma compiler audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiUpgradeDefectDetector":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed upgradeable proxy defect audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiDoSGasLimitsSentry":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed Block Gas Limit DoS audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiDeFiSlippageGuard":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed DeFi slippage protection audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiConstantTimeAuditor":
            alerts.extend(majority_dict.get("flagged_lines", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed constant-time cryptographic audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiMemoryZeroizeSentry":
            alerts.extend(majority_dict.get("flagged_findings", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed memory zeroization audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiDimensionalAnalysisSentry":
            alerts.extend(majority_dict.get("mismatches", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed dimensional analysis audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiAgentToolExecutionGuard":
            alerts.extend(majority_dict.get("blocked_patterns", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed agent terminal command safety audit (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiHotPathAllocationAuditor":
            alerts.extend(majority_dict.get("flagged_hotspots", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed hot-path allocation diagnostic scan on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiDockerImageScanner":
            alerts.extend(majority_dict.get("detected_vulnerabilities", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static container image safety scan on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiContainerEscapeDetector":
            alerts.extend(majority_dict.get("escape_vectors", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed container escape vulnerabilities scan on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiHardcodedSecretDetector":
            alerts.extend(majority_dict.get("flagged_secrets", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed hardcoded secrets scan on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiAutomatedRotationEngine":
            risk_score = 0.0 if majority_dict.get("rotation_completed") else 80.0
            summary = f"Credential rotation process executed for {input_envelope.target_identifier} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiLLMOutputSanitizer":
            alerts.extend(majority_dict.get("detected_leaks", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = (
                f"Completed LLM output sanitization audit (Consensus Passed). Status: {majority_dict.get('status')}"
            )
        elif agent_name == "PiDataFlowPrivacyMapper":
            alerts.extend(majority_dict.get("unsecured_flows", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed data flow privacy analysis (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiSensitiveDataScanner":
            alerts.extend(majority_dict.get("discovered_pii_elements", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed sensitive data and PII scan on {input_envelope.data_label} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiAutomatedAnonymizer":
            risk_score = 0.0 if majority_dict.get("is_secure") else 80.0
            summary = f"Automated payload anonymization completed (Consensus Passed). Fields scrubbed: {majority_dict.get('fields_scrubbed_count')}. Status: {majority_dict.get('status')}"
        elif agent_name == "PiSensitiveLogLeakSentry":
            alerts.extend(majority_dict.get("flagged_leaks", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed sensitive log leak audit on {input_envelope.log_file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiStructuredLoggingEnforcer":
            alerts.extend(majority_dict.get("unstructured_statements", []))
            compliance_score = majority_dict.get("compliance_score", 100.0)
            risk_score = 100.0 - compliance_score
            summary = f"Completed structured logging compliance audit on {input_envelope.file_path} (Consensus Passed). Compliance score: {compliance_score:.1f}. Status: {majority_dict.get('status')}"
        elif agent_name == "PiIaCScanner":
            alerts.extend(majority_dict.get("detected_misconfigs", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed static IaC security scan on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiDependencyVulnScanner":
            alerts.extend(majority_dict.get("vulnerable_packages", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed dependency vulnerability scan on {input_envelope.lockfile_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiCloudConfigAuditor":
            alerts.extend(majority_dict.get("misconfigured_resources", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed cloud config security audit on {input_envelope.file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiRBACPermissionMapper":
            alerts.extend(majority_dict.get("excessive_permissions", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed RBAC least privilege mapping on {input_envelope.policy_file_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiEncryptionComplianceChecker":
            alerts.extend(majority_dict.get("missing_encryption", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed encryption compliance check on {input_envelope.resource_type} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiSBOMValidator":
            alerts.extend(majority_dict.get("license_issues", []))
            alerts.extend(majority_dict.get("missing_attestations", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed SBOM licensing and validation audit on {input_envelope.sbom_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiSupplyChainIntegrityChecker":
            alerts.extend(majority_dict.get("suspicious_packages", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed software supply chain integrity check on {input_envelope.manifest_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiAPIOWASPScanner":
            alerts.extend(majority_dict.get("owasp_violations", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed API OWASP security audit on {input_envelope.api_path} (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiKubernetesSecurityAuditor":
            alerts.extend(majority_dict.get("violations", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed Kubernetes security audit (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiZeroTrustVerifier":
            alerts.extend(majority_dict.get("violations", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed Zero-Trust network policy verification (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiCertificateRotationWatcher":
            alerts.extend(majority_dict.get("issues", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed certificate rotation watch (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiFirewallRuleAuditor":
            alerts.extend(majority_dict.get("open_ports", []))
            alerts.extend(majority_dict.get("issues", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = (
                f"Completed firewall rule security audit (Consensus Passed). Status: {majority_dict.get('status')}"
            )
        elif agent_name == "PiBackupIntegrityChecker":
            alerts.extend(majority_dict.get("issues", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed disaster recovery backup integrity check (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiAuditLogTamperDetector":
            alerts.extend(majority_dict.get("anomalies", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed audit log tampering detection scan (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiMisconfigPatternMatcher":
            alerts.extend(majority_dict.get("matched_patterns", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed security misconfiguration pattern match (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiThreatModelGenerator":
            alerts.extend(majority_dict.get("threats", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed dynamic STRIDE threat model generation (Consensus Passed). Categories: {', '.join(majority_dict.get('STRIDE_categories', []))}. Status: {majority_dict.get('status')}"
        elif agent_name == "PiSecretsManagerCompletenessChecker":
            alerts.extend(majority_dict.get("gaps", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed secrets vault configuration completeness check (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiCodeSigningEnforcer":
            alerts.extend(majority_dict.get("issues", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed build artifact code signing enforcement scan (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiDataRetentionPolicyEnforcer":
            alerts.extend(majority_dict.get("issues", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed data retention lifecycle policy enforcement scan (Consensus Passed). Status: {majority_dict.get('status')}"
        elif agent_name == "PiRuntimeAnomalySentry":
            alerts.extend(majority_dict.get("anomalies_detected", []))
            risk_score = majority_dict.get("risk_score", 0.0)
            summary = f"Completed runtime container metrics anomaly audit (Consensus Passed). Status: {majority_dict.get('status')}"

        if risk_score >= 80.0 and os.getenv("PI_ORCHESTRATOR_STRICT_MODE") == "true":
            success = False

        result_details = copy.deepcopy(majority_dict)
        result_details["consensus_telemetry"] = {
            "status": "CONSENSUS_PASSED",
            "divergence_score": report.consensus_divergence_score,
            "votes": votes,
        }
        anomalies.extend(alerts)

    return success, risk_score, summary, result_details, anomalies
