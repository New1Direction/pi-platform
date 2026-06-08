from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Type

from pydantic import BaseModel

from pi_micro_agents.pi_access_control_shadow import ACShadowInput, PiAccessControlShadow

# Import specialized input envelopes
from pi_micro_agents.pi_access_control_verifier import AccessControlInput, PiAccessControlVerifier
from pi_micro_agents.pi_adversarial_evaluator_sim import AdversarialEvaluatorSimInput, PiAdversarialEvaluatorSim
from pi_micro_agents.pi_agent_tool_execution_guard import AgentToolGuardInput, PiAgentToolExecutionGuard
from pi_micro_agents.pi_api_auth_hardcoded_token_sentry import ApiAuthHardcodedTokenInput, PiApiAuthHardcodedTokenSentry
from pi_micro_agents.pi_api_auth_jwt_none_algorithm_sentry import (
    ApiAuthJWTNoneAlgorithmInput,
    PiApiAuthJWTNoneAlgorithmSentry,
)
from pi_micro_agents.pi_api_owasp_scanner import APIInput, PiAPIOWASPScanner
from pi_micro_agents.pi_api_reverse_engineered_auth import ApiReverseEngineeredAuthInput, PiApiReverseEngineeredAuth
from pi_micro_agents.pi_arbitrage_guard import ArbitrageInput, PiArbitrageGuard
from pi_micro_agents.pi_architecture_import_boundary_sentry import (
    ImportBoundaryInput,
    PiArchitectureImportBoundarySentry,
)
from pi_micro_agents.pi_arithmetic_auditor import ArithmeticInput, PiArithmeticAuditor
from pi_micro_agents.pi_assembly_lethal_weapons import AssemblySafetyInput, PiAssemblyLethalWeapons
from pi_micro_agents.pi_ast_depth_guard import AstDepthInput, PiAstDepthGuard
from pi_micro_agents.pi_audit_log_tamper_detector import LogInput, PiAuditLogTamperDetector
from pi_micro_agents.pi_automated_anonymizer import AnonymizerInput, PiAutomatedAnonymizer
from pi_micro_agents.pi_automated_rotation_engine import PiAutomatedRotationEngine, RotationInput
from pi_micro_agents.pi_backup_integrity_checker import BackupInput, PiBackupIntegrityChecker
from pi_micro_agents.pi_block_timestamp_sentry import BlockTimestampInput, PiBlockTimestampSentry
from pi_micro_agents.pi_bytecode_decompiler import BytecodeDecompilerInput, PiBytecodeDecompiler

# Cohort 11 (Agents 116-140) Imports
from pi_micro_agents.pi_caveman_token_compressor import CavemanCompressorInput, PiCavemanTokenCompressor
from pi_micro_agents.pi_centralization_sentry import CentralizationInput, PiCentralizationSentry
from pi_micro_agents.pi_certificate_rotation_watcher import CertInput, PiCertificateRotationWatcher
from pi_micro_agents.pi_changelog_auditor import ChangelogInput, PiChangelogAuditor
from pi_micro_agents.pi_cloud_config_auditor import CloudConfigInput, PiCloudConfigAuditor
from pi_micro_agents.pi_code_signing_enforcer import ArtifactInput, PiCodeSigningEnforcer

# Adopted Skills Agents
from pi_micro_agents.pi_constant_time_auditor import ConstantTimeInput, PiConstantTimeAuditor
from pi_micro_agents.pi_container_escape_detector import ContainerEscapeInput, PiContainerEscapeDetector
from pi_micro_agents.pi_cross_chain_bridge_auditor import BridgeAuditInput, PiCrossChainBridgeAuditor
from pi_micro_agents.pi_cross_chain_message_replay_sentry import BridgeReplayInput, PiCrossChainMessageReplaySentry
from pi_micro_agents.pi_data_flow_privacy_mapper import PiDataFlowPrivacyMapper, PrivacyMapperInput
from pi_micro_agents.pi_data_retention_policy_enforcer import PiDataRetentionPolicyEnforcer, RetentionInput
from pi_micro_agents.pi_bot_detection_evasion_sentry import BotEvasionInput, PiBotDetectionEvasionSentry
from pi_micro_agents.pi_hipaa_compliance_auditor import HipaaAuditInput, PiHipaaComplianceAuditor
from pi_micro_agents.pi_mobile_security_auditor import MobileAuditInput, PiMobileSecurityAuditor
from pi_micro_agents.pi_ssh_certificate_security_auditor import PiSshCertificateSecurityAuditor, SshCertInput
from pi_micro_agents.pi_pci_dss_auditor import PciDssInput, PiPciDssAuditor
from pi_micro_agents.pi_database_migration_unindexed_sentry import (
    DatabaseMigrationUnindexedInput,
    PiDatabaseMigrationUnindexedSentry,
)
from pi_micro_agents.pi_dead_code_pruner import DeadCodeInput, PiDeadCodePruner
from pi_micro_agents.pi_defi_math_rounding_sentry import MathRoundingInput, PiDeFiMathRoundingSentry
from pi_micro_agents.pi_defi_slippage_guard import DeFiSlippageInput, PiDeFiSlippageGuard
from pi_micro_agents.pi_delegate_call_guard import DelegateCallInput, PiDelegateCallGuard
from pi_micro_agents.pi_dependency_vuln_scanner import DependencyInput, PiDependencyVulnScanner
from pi_micro_agents.pi_deployment_safety_guard import DeploymentSafetyInput, PiDeploymentSafetyGuard
from pi_micro_agents.pi_depreciation_scanner import DepreciationInput, PiDepreciationScanner
from pi_micro_agents.pi_design_an_interface_validator import DesignAnInterfaceInput, PiDesignAnInterfaceValidator
from pi_micro_agents.pi_deterministic_output_valid import DeterministicOutputValidInput, PiDeterministicOutputValid
from pi_micro_agents.pi_dimensional_analysis_sentry import DimensionalAnalysisInput, PiDimensionalAnalysisSentry
from pi_micro_agents.pi_docker_compose_port_exposure_sentry import (
    DockerComposePortExposureInput,
    PiDockerComposePortExposureSentry,
)
from pi_micro_agents.pi_docker_compose_security_sentry import DockerComposeSecurityInput, PiDockerComposeSecuritySentry
from pi_micro_agents.pi_docker_image_scanner import DockerImageInput, PiDockerImageScanner
from pi_micro_agents.pi_docker_socket_privilege_sentry import DockerSocketPrivilegeInput, PiDockerSocketPrivilegeSentry
from pi_micro_agents.pi_dos_gas_limits_sentry import DoSGasLimitsInput, PiDoSGasLimitsSentry
from pi_micro_agents.pi_eip712_domain_separator_sentry import DomainSeparatorInput, PiEIP712DomainSeparatorSentry
from pi_micro_agents.pi_eip712_signature_linter import EIP712LinterInput, PiEIP712SignatureLinter
from pi_micro_agents.pi_eip4337_account_abstraction_sentry import (
    AccountAbstractionInput,
    PiEIP4337AccountAbstractionSentry,
)
from pi_micro_agents.pi_encryption_compliance_checker import EncryptionInput, PiEncryptionComplianceChecker
from pi_micro_agents.pi_erc20_permit_phishing_guard import PermitGuardInput, PiERC20PermitPhishingGuard
from pi_micro_agents.pi_erc4626_vault_guard import PiERC4626VaultGuard, VaultGuardInput
from pi_micro_agents.pi_erc7702_delegation_guard import ERC7702Input, PiERC7702DelegationGuard
from pi_micro_agents.pi_error_handling_catch_all_guard import ErrorCatchInput, PiErrorHandlingCatchAllGuard
from pi_micro_agents.pi_external_contract_guard import ExternalContractGuardInput, PiExternalContractGuard
from pi_micro_agents.pi_firewall_rule_auditor import FirewallInput, PiFirewallRuleAuditor
from pi_micro_agents.pi_flash_loan_defender import FlashLoanInput, PiFlashLoanDefender
from pi_micro_agents.pi_floating_pragma_sentry import PiFloatingPragmaSentry, PragmaSentryInput
from pi_micro_agents.pi_gas_guzzler_detector import GasGuzzlerInput, PiGasGuzzlerDetector
from pi_micro_agents.pi_git_safety_guardrail import GitSafetyInput, PiGitSafetyGuardrail
from pi_micro_agents.pi_git_sec_scanner import GitSecInput, PiGitSecScanner
from pi_micro_agents.pi_git_secret_entropy_leak_sentry import GitSecretEntropyLeakInput, PiGitSecretEntropyLeakSentry
from pi_micro_agents.pi_git_secret_leak_sentry import GitSecretLeakInput, PiGitSecretLeakSentry
from pi_micro_agents.pi_github_actions_unpinned_version import (
    GithubActionsUnpinnedInput,
    PiGithubActionsUnpinnedVersion,
)
from pi_micro_agents.pi_grill_me_questionnaire import GrillMeInput, PiGrillMeQuestionnaire
from pi_micro_agents.pi_grpc_protocol_interceptor import GrpcProtocolInterceptInput, PiGrpcProtocolInterceptor
from pi_micro_agents.pi_grpc_wire_protocol_insecure_sentry import (
    GrpcWireProtocolInsecureInput,
    PiGrpcWireProtocolInsecureSentry,
)
from pi_micro_agents.pi_handoff_checkpoint_sentry import HandoffInput, PiHandoffCheckpointSentry
from pi_micro_agents.pi_hardcoded_secret_detector import HardcodedSecretInput, PiHardcodedSecretDetector
from pi_micro_agents.pi_hot_path_allocation_auditor import HotPathAllocationInput, PiHotPathAllocationAuditor

# Phase 4 Complementary Micro-Agents (11-30)
from pi_micro_agents.pi_iac_scanner import IaCInput, PiIaCScanner
from pi_micro_agents.pi_kubernetes_root_execution_linter import (
    KubernetesRootExecutionInput,
    PiKubernetesRootExecutionLinter,
)
from pi_micro_agents.pi_kubernetes_security_auditor import K8sInput, PiKubernetesSecurityAuditor
from pi_micro_agents.pi_llm_base64_encoding_deobfuscator import (
    LLMBase64DeobfuscatorInput,
    PiLLMBase64EncodingDeobfuscator,
)
from pi_micro_agents.pi_llm_chain_of_thought_bypass_sentry import (
    LLMChainOfThoughtBypassInput,
    PiLLMChainOfThoughtBypassSentry,
)
from pi_micro_agents.pi_llm_context_window_drift_sentry import LLMContextWindowDriftInput, PiLLMContextWindowDriftSentry
from pi_micro_agents.pi_llm_hallucination_detector import HallucinationDetectorInput, PiLLMHallucinationDetector
from pi_micro_agents.pi_llm_negative_constraint_evasion import (
    LLMNegativeConstraintInput,
    PiLLMNegativeConstraintEvasion,
)
from pi_micro_agents.pi_llm_output_sanitizer import LLMOutputSanitizerInput, PiLLMOutputSanitizer
from pi_micro_agents.pi_llm_pairwise_adversarial_validator import (
    LLMPairwiseAdversarialInput,
    PiLLMPairwiseAdversarialValidator,
)
from pi_micro_agents.pi_llm_prompt_egress_leak_detector import LLMPromptEgressLeakInput, PiLLMPromptEgressLeakDetector
from pi_micro_agents.pi_llm_prompt_injection_negative_constraint_sentry import (
    NegativeConstraintInput,
    PiLLMPromptInjectionNegativeConstraintSentry,
)
from pi_micro_agents.pi_llm_prompt_injection_sentry import PiLLMPromptInjectionSentry, PromptInjectionInput
from pi_micro_agents.pi_llm_prompt_injection_system_prompt_override_sentry import (
    PiLLMPromptInjectionSystemPromptOverrideSentry,
    SystemPromptOverrideInput,
)
from pi_micro_agents.pi_llm_recursive_refinement_jailbreak import (
    LLMRecursiveRefinementInput,
    PiLLMRecursiveRefinementJailbreak,
)
from pi_micro_agents.pi_llm_system_prompt_drift_sentry import PiLLMSystemPromptDriftSentry, SystemPromptDriftInput
from pi_micro_agents.pi_llm_system_prompt_hijack_sentry import LLMSystemPromptHijackInput, PiLLMSystemPromptHijackSentry
from pi_micro_agents.pi_logic_gatekeeper import LogicGatekeeperInput, PiLogicGatekeeper
from pi_micro_agents.pi_magic_number_scanner import MagicNumberInput, PiMagicNumberScanner
from pi_micro_agents.pi_memory_zeroize_sentry import MemoryZeroizeInput, PiMemoryZeroizeSentry
from pi_micro_agents.pi_mempool_sentry import MempoolTxInput, PiMempoolSentry
from pi_micro_agents.pi_misconfig_pattern_matcher import ConfigInput, PiMisconfigPatternMatcher
from pi_micro_agents.pi_mock_data_tainting_sentry import MockDataTaintingInput, PiMockDataTaintingSentry
from pi_micro_agents.pi_nginx_reverse_proxy_header_sentry import (
    NginxReverseProxyHeaderInput,
    PiNginxReverseProxyHeaderSentry,
)
from pi_micro_agents.pi_oracle_divergence_audit import OracleDivergenceInput, PiOracleDivergenceAudit
from pi_micro_agents.pi_oracle_sentry import OracleSentryInput, PiOracleSentry
from pi_micro_agents.pi_phishing_shield import PhishingShieldInput, PiPhishingShield
from pi_micro_agents.pi_pipeline_integrity_auditor import PipelineIntegrityInput, PiPipelineIntegrityAuditor
from pi_micro_agents.pi_prompt_leak_buster import LeakBusterInput, PiPromptLeakBuster
from pi_micro_agents.pi_publisher_dispatch import PiPublisherDispatch, PublisherInput
from pi_micro_agents.pi_rbac_permission_mapper import PiRBACPermissionMapper, RBACInput
from pi_micro_agents.pi_read_only_oracle_manipulation_sentry import (
    PiReadOnlyOracleManipulationSentry,
    ReadOnlyOracleInput,
)
from pi_micro_agents.pi_read_only_reentrancy_sentry import PiReadOnlyReentrancySentry, ReadOnlyReentrancyInput
from pi_micro_agents.pi_readme_validator import PiReadmeValidator, ReadmeInput

# 10 New Specialized Dual-Use PI Agent imports
from pi_micro_agents.pi_reentrancy_guard_spec import PiReentrancyGuardSpec, ReentrancyGuardSpecInput
from pi_micro_agents.pi_reentrancy_sentry import PiReentrancySentry, ReentrancyInput
from pi_micro_agents.pi_request_refactor_plan_verifier import PiRequestRefactorPlanVerifier, RequestRefactorInput
from pi_micro_agents.pi_runtime_anomaly_sentry import PiRuntimeAnomalySentry, RuntimeInput
from pi_micro_agents.pi_rust_anchor_security_sentry import AnchorSecurityInput, PiRustAnchorSecuritySentry
from pi_micro_agents.pi_rust_solana_account_data_validation import (
    PiRustSolanaAccountDataValidation,
    SolanaAccountDataInput,
)
from pi_micro_agents.pi_rust_solana_arithmetic_overflow_check import (
    PiRustSolanaArithmeticOverflowCheck,
    SolanaArithmeticOverflowInput,
)
from pi_micro_agents.pi_rust_solana_borsh_serialization_leak import (
    PiRustSolanaBorshSerializationLeak,
    SolanaBorshLeakInput,
)
from pi_micro_agents.pi_rust_solana_cpi_instruction_sentry import (
    PiRustSolanaCPIInstructionSentry,
    SolanaCPIInstructionInput,
)
from pi_micro_agents.pi_rust_solana_missing_signer_assert import (
    PiRustSolanaMissingSignerAssert,
    SolanaMissingSignerInput,
)
from pi_micro_agents.pi_rust_solana_owner_verification_guard import (
    PiRustSolanaOwnerVerificationGuard,
    SolanaOwnerVerificationInput,
)
from pi_micro_agents.pi_rust_solana_reentrancy_cross_program_sentry import (
    PiRustSolanaReentrancyCrossProgramSentry,
    SolanaReentrancyCrossInput,
)
from pi_micro_agents.pi_rust_solana_reentrancy_sentry import PiRustSolanaReentrancySentry, RustSolanaReentrancyInput
from pi_micro_agents.pi_rust_solana_signer_assertion_sentry import (
    PiRustSolanaSignerAssertionSentry,
    SolanaSignerAssertionInput,
)
from pi_micro_agents.pi_rust_solana_sysvar_clock_verification import (
    PiRustSolanaSysvarClockVerification,
    SolanaSysvarClockInput,
)
from pi_micro_agents.pi_rust_tokio_deadlock_sentry import PiRustTokioDeadlockSentry, RustTokioDeadlockInput

# Cohort 6 (Agents 51-60) Imports
from pi_micro_agents.pi_rust_tui_resource_limit import PiRustTuiResourceLimit, RustTuiResourceLimitInput
from pi_micro_agents.pi_sandwich_mev_shield import MEVShieldInput, PiSandwichMEVShield
from pi_micro_agents.pi_sbom_validator import PiSBOMValidator, SBOMInput
from pi_micro_agents.pi_secrets_manager_completeness_checker import PiSecretsManagerCompletenessChecker, VaultInput
from pi_micro_agents.pi_self_destruct_hunter import PiSelfDestructHunter, SelfDestructHunterInput
from pi_micro_agents.pi_self_healing_patch_agent import PiSelfHealingPatchAgent, SelfHealingInput
from pi_micro_agents.pi_semantic_commit_message_linter import CommitLinterInput, PiSemanticCommitMessageLinter
from pi_micro_agents.pi_semantic_schema_dynamic_field_check import (
    PiSemanticSchemaDynamicFieldCheck,
    SemanticSchemaDynamicFieldInput,
)
from pi_micro_agents.pi_semantic_schema_registry import PiSemanticSchemaRegistry, SemanticSchemaRegistryInput
from pi_micro_agents.pi_sensitive_data_scanner import PiSensitiveDataScanner, SensitiveDataInput
from pi_micro_agents.pi_sensitive_log_leak_sentry import LogLeakInput, PiSensitiveLogLeakSentry
from pi_micro_agents.pi_shadowed_variable_detector import PiShadowedVariableDetector, ShadowedVariableInput
from pi_micro_agents.pi_signature_replay_scout import PiSignatureReplayScout, SignatureInput
from pi_micro_agents.pi_solidity_arbitrary_transfer_sentry import (
    ArbitraryTransferInput,
    PiSolidityArbitraryTransferSentry,
)
from pi_micro_agents.pi_solidity_array_length_mutation_sentry import (
    ArrayLengthMutationInput,
    PiSolidityArrayLengthMutationSentry,
)
from pi_micro_agents.pi_solidity_array_length_sentry import ArrayLengthInput, PiSolidityArrayLengthSentry
from pi_micro_agents.pi_solidity_assembly_memory_safe_sentry import (
    AssemblyMemorySafeInput,
    PiSolidityAssemblyMemorySafeSentry,
)
from pi_micro_agents.pi_solidity_block_timestamp_interval_sentry import (
    PiSolidityBlockTimestampIntervalSentry,
    TimestampIntervalInput,
)
from pi_micro_agents.pi_solidity_compiler_bugs_sentry import CompilerBugsInput, PiSolidityCompilerBugsSentry
from pi_micro_agents.pi_solidity_constant_pragma_validation import (
    ConstantPragmaInput,
    PiSolidityConstantPragmaValidation,
)
from pi_micro_agents.pi_solidity_create2_salt_collision_sentry import (
    Create2SaltCollisionInput,
    PiSolidityCreate2SaltCollisionSentry,
)

# Cohort 5 (Agents 41-50) Imports
from pi_micro_agents.pi_solidity_delegate_call_to_self_sentry import (
    DelegateCallSelfInput,
    PiSolidityDelegateCallToSelfSentry,
)
from pi_micro_agents.pi_solidity_delegatecall_storage_sentry import (
    DelegatecallStorageInput,
    PiSolidityDelegatecallStorageSentry,
)
from pi_micro_agents.pi_solidity_dirty_memory_sentry import DirtyMemoryInput, PiSolidityDirtyMemorySentry
from pi_micro_agents.pi_solidity_divide_before_multiply_auditor import (
    DivideBeforeMultiplyInput,
    PiSolidityDivideBeforeMultiplyAuditor,
)
from pi_micro_agents.pi_solidity_eip712_typehash_mismatch_sentry import (
    EIP712TypehashMismatchInput,
    PiSolidityEIP712TypehashMismatchSentry,
)
from pi_micro_agents.pi_solidity_erc20_safe_approve_auditor import (
    ERC20SafeApproveInput,
    PiSolidityERC20SafeApproveAuditor,
)
from pi_micro_agents.pi_solidity_erc20_transfer_recipient_sentry import (
    ERC20TransferRecipientInput,
    PiSolidityERC20TransferRecipientSentry,
)
from pi_micro_agents.pi_solidity_erc7702_code_sentry import ERC7702CodeInput, PiSolidityERC7702CodeSentry
from pi_micro_agents.pi_solidity_external_contracts_return_check import (
    ExternalContractsReturnInput,
    PiSolidityExternalContractsReturnCheck,
)
from pi_micro_agents.pi_solidity_flash_loan_attack import PiSolidityFlashLoanAttack, SolidityFlashLoanInput
from pi_micro_agents.pi_solidity_initializable_gap_sentry import InitializableGapInput, PiSolidityInitializableGapSentry
from pi_micro_agents.pi_solidity_l2_gas_fee_sentry import L2GasFeeInput, PiSolidityL2GasFeeSentry
from pi_micro_agents.pi_solidity_oracle_liveness_sentry import OracleLivenessInput, PiSolidityOracleLivenessSentry
from pi_micro_agents.pi_solidity_owner_timelock_sentry import OwnerTimelockInput, PiSolidityOwnerTimelockSentry
from pi_micro_agents.pi_solidity_price_feed_fallback_sentry import (
    PiSolidityPriceFeedFallbackSentry,
    PriceFeedFallbackInput,
)
from pi_micro_agents.pi_solidity_price_feed_sequencer_sentry import (
    PiSolidityPriceFeedSequencerSentry,
    PriceFeedSequencerInput,
)
from pi_micro_agents.pi_solidity_proxy_call_target_check import PiSolidityProxyCallTargetCheck, ProxyCallTargetInput

# Cohort 7 (Agents 61-110) Imports
from pi_micro_agents.pi_solidity_reentrancy_guard_overlap_sentry import (
    PiSolidityReentrancyGuardOverlapSentry,
    ReentrancyGuardOverlapInput,
)
from pi_micro_agents.pi_solidity_reentrancy_mutex_sentry import MutexSentryInput, PiSolidityReentrancyMutexSentry
from pi_micro_agents.pi_solidity_selfdestruct_code_erase_sentry import (
    PiSoliditySelfdestructCodeEraseSentry,
    SelfdestructCodeEraseInput,
)
from pi_micro_agents.pi_solidity_signature_malleability_sentry import (
    PiSoliditySignatureMalleabilitySentry,
    SignatureMalleabilityInput,
)
from pi_micro_agents.pi_solidity_signature_omitted_replay_sentry import (
    PiSoliditySignatureOmittedReplaySentry,
    SignatureOmittedReplayInput,
)

# 10 Additional Highly Specialized Dual-Use PI Agent imports (Agents 31-40)
from pi_micro_agents.pi_solidity_transient_storage_reentrancy_sentry import (
    PiSolidityTransientStorageReentrancySentry,
    TransientStorageReentrancyInput,
)

# 10 Additional Highly Specialized Dual-Use PI Agent imports (Agents 11-20)
from pi_micro_agents.pi_solidity_transient_storage_sentry import PiSolidityTransientStorageSentry, TransientStorageInput
from pi_micro_agents.pi_solidity_tx_origin_call_check_sentry import (
    PiSolidityTxOriginCallCheckSentry,
    TxOriginCallCheckInput,
)
from pi_micro_agents.pi_solidity_unbounded_loops_in_state_mutation import (
    PiSolidityUnboundedLoopsInStateMutation,
    UnboundedLoopsStateInput,
)
from pi_micro_agents.pi_solidity_undeclared_return_variable_sentry import (
    PiSolidityUndeclaredReturnVariableSentry,
    UndeclaredReturnVariableInput,
)
from pi_micro_agents.pi_solidity_upgradeable_initializer_sentry import (
    PiSolidityUpgradeableInitializerSentry,
    UpgradeableInitInput,
)
from pi_micro_agents.pi_solidity_yul_memory_offset_audit import PiSolidityYulMemoryOffsetAudit, YulMemoryOffsetInput
from pi_micro_agents.pi_storage_layout_drift import PiStorageLayoutDrift, StorageDriftInput
from pi_micro_agents.pi_structured_logging_enforcer import PiStructuredLoggingEnforcer, StructuredLoggingInput
from pi_micro_agents.pi_supply_chain_integrity_checker import PiSupplyChainIntegrityChecker, SupplyChainInput
from pi_micro_agents.pi_tdd_assertion_coverage import PiTddAssertionCoverage, TddAssertionInput
from pi_micro_agents.pi_tdd_mocking_sanity_checker import PiTddMockingSanityChecker, TddMockingInput
from pi_micro_agents.pi_tdd_test_file_verifier import PiTddTestFileVerifier, TddTestFileInput
from pi_micro_agents.pi_terraform_state_credential_sentry import (
    PiTerraformStateCredentialSentry,
    TerraformStateCredentialInput,
)
from pi_micro_agents.pi_threat_model_generator import PiThreatModelGenerator, SystemInput
from pi_micro_agents.pi_to_issues_breakdown import PiToIssuesBreakdown, ToIssuesInput
from pi_micro_agents.pi_to_prd_validator import PiToPrdValidator, ToPrdInput
from pi_micro_agents.pi_token_tax_detector import PiTokenTaxDetector, TokenTaxInput
from pi_micro_agents.pi_triage_bug_labels import PiTriageBugLabels, TriageInput
from pi_micro_agents.pi_tx_origin_sentry import PiTxOriginSentry, TxOriginInput
from pi_micro_agents.pi_typescript_wizardry_check import PiTypeScriptWizardryCheck, TypeScriptWizardryInput
from pi_micro_agents.pi_uncontrolled_recursion_sentry import PiUncontrolledRecursionSentry, RecursionInput
from pi_micro_agents.pi_uninitialized_state_sentry import PiUninitializedStateSentry, UninitializedInput
from pi_micro_agents.pi_uniswap_v3_pool_sentry import PiUniswapV3PoolSentry, UniV3SentryInput
from pi_micro_agents.pi_upgrade_defect_detector import PiUpgradeDefectDetector, UpgradeDefectInput

# 10 More Highly Specialized Dual-Use PI Agent imports (Agents 21-30)
from pi_micro_agents.pi_vyper_external_call_sentry import PiVyperExternalCallSentry, VyperExternalCallInput
from pi_micro_agents.pi_vyper_sec_scanner import PiVyperSecScanner, VyperScannerInput
from pi_micro_agents.pi_vyper_state_lock_sentry import PiVyperStateLockSentry, VyperLockInput
from pi_micro_agents.pi_vyper_storage_layout_collision_sentry import (
    PiVyperStorageLayoutCollisionSentry,
    VyperStorageCollisionInput,
)
from pi_micro_agents.pi_web_vuln_scanner import PiWebVulnScanner, WebVulnInput
from pi_micro_agents.pi_zero_knowledge_circuit_sentry import PiZeroKnowledgeCircuitSentry, ZKCircuitInput
from pi_micro_agents.pi_zero_trust_execution_domain import PiZeroTrustExecutionDomain, ZeroTrustExecDomainInput
from pi_micro_agents.pi_zero_trust_verifier import PiZeroTrustVerifier, ZeroTrustInput
from pi_micro_agents.pi_zk_circom_division_sentry import PiZKCircomDivisionSentry, ZKCircomDivisionInput
from pi_micro_agents.pi_zk_circom_shadow_signal_sentry import CircomShadowSignalInput, PiZKCircomShadowSignalSentry
from pi_micro_agents.pi_zk_circom_underconstrained_sentry import (
    CircomUnderconstrainedInput,
    PiZKCircomUnderconstrainedSentry,
)
from pi_micro_agents.pi_zk_div_by_zero_constraint_auditor import (
    PiZKDivByZeroConstraintAuditor,
    ZKDivByZeroConstraintInput,
)
from pi_micro_agents.pi_zk_non_prime_field_range_sentry import PiZKNonPrimeFieldRangeSentry, ZKNonPrimeFieldRangeInput
from pi_micro_agents.pi_zk_proof_forging_validation_sentry import (
    PiZKProofForgingValidationSentry,
    ZKProofForgingValidationInput,
)
from pi_micro_agents.pi_zk_proof_public_input_verif import PiZKProofPublicInputVerif, ZKProofPublicInputVerifInput
from pi_micro_agents.pi_zk_public_input_leakage_auditor import PiZKPublicInputLeakageAuditor, ZKPublicInputLeakageInput
from pi_micro_agents.pi_zk_signal_shadowing_signal_sentry import PiZKSignalShadowingSignalSentry, ZKSignalShadowingInput
from pi_micro_agents.pi_zk_signal_unconstrained_constraint import (
    PiZKSignalUnconstrainedConstraint,
    ZKSignalUnconstrainedInput,
)
from pi_micro_agents.pi_zk_unused_constraint_variables import PiZKUnusedConstraintVariables, ZKUnusedConstraintInput
from pi_micro_agents.pi_zoom_out_system_explainer import PiZoomOutSystemExplainer, ZoomOutInput


class AgentRoute:
    """Envelopes configuration metadata for a single micro-agent route selection."""

    def __init__(
        self,
        agent_name: str,
        keywords: List[str],
        agent_class: Type[Any],
        input_factory: Callable[[str, Dict[str, Any]], BaseModel],
    ) -> None:
        self.agent_name = agent_name
        self.keywords = keywords
        self.agent_class = agent_class
        self.input_factory = input_factory


class AgentRouter:
    """Central decorator-based registry resolving keyword matching and factory instantiation."""

    routes: List[AgentRoute] = []

    @classmethod
    def register(
        cls,
        agent_name: str,
        keywords: List[str],
        agent_class: Type[Any],
        input_factory: Callable[[str, Dict[str, Any]], BaseModel],
    ) -> Callable[[Type[Any]], Type[Any]]:
        route = AgentRoute(
            agent_name=agent_name,
            keywords=keywords,
            agent_class=agent_class,
            input_factory=input_factory,
        )
        cls.routes.append(route)
        return lambda x: x

    @classmethod
    def resolve(cls, goal: str, context: Dict[str, Any] | None = None) -> AgentRoute | None:
        """Determines the target route based on goal keyword matches (sequential precedence)."""
        # NEW: Needle fast path first
        try:
            from pi_micro_agents.orchestrator.needle_router import NeedleRouter

            needle_router = NeedleRouter()
            needle_agent = needle_router.route_sync(goal, context or {})
            if needle_agent:
                for route in cls.routes:
                    if route.agent_name == needle_agent:
                        return route
        except Exception:
            pass

        g_lower = goal.lower()
        for route in cls.routes:
            if any(re.search(rf"\b{re.escape(kw)}\b", g_lower) for kw in route.keywords):
                return route
        return None


# Register all 36 micro-agents in exact sequential precedence matching original pi_orchestrator.py
AgentRouter.register(
    agent_name="PiGitSecScanner",
    keywords=["scan requirements", "scan package.json", "dependency scan", "git scan", "security audit"],
    agent_class=PiGitSecScanner,
    input_factory=lambda goal, ctx: GitSecInput(
        filename=ctx.get("filename", "requirements.txt"),
        content=ctx.get("content", ""),
    ),
)

AgentRouter.register(
    agent_name="PiPromptLeakBuster",
    keywords=["leak scan", "privacy scan", "egress leak", "credential scan", "scan draft"],
    agent_class=PiPromptLeakBuster,
    input_factory=lambda goal, ctx: LeakBusterInput(
        text=ctx.get("text", goal),
    ),
)

AgentRouter.register(
    agent_name="NicheCurationPipelineChain",
    keywords=["curate niche", "niche curation", "newsletter curate", "substack publish", "curation pipeline"],
    agent_class=PiPublisherDispatch,
    input_factory=lambda goal, ctx: PublisherInput(
        substack_title="",
        substack_markdown_body="",
        x_thread_posts=[],
        draft_only=True,
    ),
)

AgentRouter.register(
    agent_name="PiPublisherDispatch",
    keywords=["publish", "deploy", "dispatch", "commit"],
    agent_class=PiPublisherDispatch,
    input_factory=lambda goal, ctx: PublisherInput(
        substack_title=ctx.get("substack_title", ctx.get("title", "Draft Publication")),
        substack_markdown_body=ctx.get("substack_markdown_body", ctx.get("content", ctx.get("source_code", ""))),
        x_thread_posts=ctx.get("x_thread_posts", []),
        draft_only=ctx.get("draft_only", True),
    ),
)

AgentRouter.register(
    agent_name="PiMempoolSentry",
    keywords=["mempool sentry", "frontrun sentinel", "sandwich watch"],
    agent_class=PiMempoolSentry,
    input_factory=lambda goal, ctx: MempoolTxInput(
        transaction_hash=ctx.get("transaction_hash", "0xabc123"),
        calldata=ctx.get("calldata", ""),
        gas_price_gwei=ctx.get("gas_price_gwei", 20.0),
    ),
)

AgentRouter.register(
    agent_name="PiArbitrageGuard",
    keywords=["defi arbitrage", "arbitrage guard", "liquidity check"],
    agent_class=PiArbitrageGuard,
    input_factory=lambda goal, ctx: ArbitrageInput(
        token_in=ctx.get("token_in", "ETH"),
        token_out=ctx.get("token_out", "USDC"),
        amount_in=ctx.get("amount_in", ctx.get("amount", 10.0)),
        pool_price_a=ctx.get("pool_price_a", 100.0),
        pool_price_b=ctx.get("pool_price_b", 101.0),
        min_spread_percent=ctx.get("min_spread_percent", 0.5),
    ),
)

AgentRouter.register(
    agent_name="PiOracleSentry",
    keywords=["oracle check", "oracle sentinel", "price verification", "oracle scan", "oracle sentry"],
    agent_class=PiOracleSentry,
    input_factory=lambda goal, ctx: OracleSentryInput(
        token=ctx.get("token", "ETH"),
        chain_id=ctx.get("chain_id", 1),
        current_observed_price=ctx.get("current_observed_price", ctx.get("observed_price", 3000.0)),
        max_deviation_percent=ctx.get("max_deviation_percent", 2.0),
    ),
)

AgentRouter.register(
    agent_name="PiSelfHealingPatchAgent",
    keywords=["self heal", "vulnerability patch", "code repair", "heal git", "safe patch"],
    agent_class=PiSelfHealingPatchAgent,
    input_factory=lambda goal, ctx: SelfHealingInput(
        file_path=ctx.get("file_path", "main.py"),
        source_code=ctx.get("source_code", ctx.get("content", "")),
        vulnerability_type=ctx.get("vulnerability_type", "UNPINNED_DEP"),
        vulnerable_lines=ctx.get("vulnerable_lines", [1]),
    ),
)

AgentRouter.register(
    agent_name="PiReentrancySentry",
    keywords=["reentrancy check", "checks-effects-interactions", "solidity audit", "reentrancy scan", "audit contract"],
    agent_class=PiReentrancySentry,
    input_factory=lambda goal, ctx: ReentrancyInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiAccessControlVerifier",
    keywords=["access check", "privilege check", "access control audit", "role verification", "audit roles"],
    agent_class=PiAccessControlVerifier,
    input_factory=lambda goal, ctx: AccessControlInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
        allowed_modifiers=ctx.get("allowed_modifiers", []),
    ),
)

AgentRouter.register(
    agent_name="PiFlashLoanDefender",
    keywords=[
        "flash loan check",
        "flash loan audit",
        "spot price manipulation",
        "oracle manipulation check",
        "audit flash loan",
    ],
    agent_class=PiFlashLoanDefender,
    input_factory=lambda goal, ctx: FlashLoanInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
        allowed_pairs=ctx.get("allowed_pairs", []),
    ),
)

AgentRouter.register(
    agent_name="PiArithmeticAuditor",
    keywords=["arithmetic audit", "overflow check", "underflow check", "math safety check", "safemath verification"],
    agent_class=PiArithmeticAuditor,
    input_factory=lambda goal, ctx: ArithmeticInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
        allowed_libraries=ctx.get("allowed_libraries", []),
    ),
)

AgentRouter.register(
    agent_name="PiDelegateCallGuard",
    keywords=[
        "delegatecall guard",
        "delegatecall scan",
        "proxy compliance",
        "eip-1967 audit",
        "unsafe delegation scan",
    ],
    agent_class=PiDelegateCallGuard,
    input_factory=lambda goal, ctx: DelegateCallInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSignatureReplayScout",
    keywords=["signature replay", "ecrecover check", "eip-712 audit", "signature scout", "replay vulnerability"],
    agent_class=PiSignatureReplayScout,
    input_factory=lambda goal, ctx: SignatureInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiBytecodeDecompiler",
    keywords=["decompile bytecode", "evm opcode check", "bytecode decompiler", "inline assembly audit"],
    agent_class=PiBytecodeDecompiler,
    input_factory=lambda goal, ctx: BytecodeDecompilerInput(
        file_path=ctx.get("file_path", "bytecode.hex"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiVyperSecScanner",
    keywords=["vyper security", "vyper scan", "vyper compiler", "vyper best practices"],
    agent_class=PiVyperSecScanner,
    input_factory=lambda goal, ctx: VyperScannerInput(
        file_path=ctx.get("file_path", "contract.vy"),
        vyper_code=ctx.get("vyper_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSelfDestructHunter",
    keywords=["selfdestruct hunter", "selfdestruct scan", "contract suicide", "contract decommissioning"],
    agent_class=PiSelfDestructHunter,
    input_factory=lambda goal, ctx: SelfDestructHunterInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiOracleDivergenceAudit",
    keywords=[
        "price divergence",
        "oracle manipulation check",
        "pricing aggregator audit",
        "geometric mean verification",
    ],
    agent_class=PiOracleDivergenceAudit,
    input_factory=lambda goal, ctx: OracleDivergenceInput(
        file_path=ctx.get("file_path", "aggregator.sol"),
        prices=ctx.get("prices", []),
        benchmarks=ctx.get("benchmarks", []),
        max_deviation_percent=ctx.get("max_deviation_percent", 2.0),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
    ),
)

AgentRouter.register(
    agent_name="PiTokenTaxDetector",
    keywords=["token tax scan", "fee-on-transfer check", "tax whitelist check", "erc-20 compliance"],
    agent_class=PiTokenTaxDetector,
    input_factory=lambda goal, ctx: TokenTaxInput(
        file_path=ctx.get("file_path", "token.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiTxOriginSentry",
    keywords=["tx.origin check", "origin phishing check", "eip-2771 audit", "meta-transaction verifier"],
    agent_class=PiTxOriginSentry,
    input_factory=lambda goal, ctx: TxOriginInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiReadOnlyReentrancySentry",
    keywords=["read-only reentrancy", "pool balance query scan", "external view safety"],
    agent_class=PiReadOnlyReentrancySentry,
    input_factory=lambda goal, ctx: ReadOnlyReentrancyInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiUninitializedStateSentry",
    keywords=["uninitialized storage", "uninitialized state", "upgradeable initializer audit", "constructor safety"],
    agent_class=PiUninitializedStateSentry,
    input_factory=lambda goal, ctx: UninitializedInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiShadowedVariableDetector",
    keywords=["shadowed variable", "variable shadowing scan", "unused variable audit", "gas unused param check"],
    agent_class=PiShadowedVariableDetector,
    input_factory=lambda goal, ctx: ShadowedVariableInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiBlockTimestampSentry",
    keywords=["timestamp reliance", "block.timestamp audit", "eip-4337 expiration check", "timelock validator"],
    agent_class=PiBlockTimestampSentry,
    input_factory=lambda goal, ctx: BlockTimestampInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiStorageLayoutDrift",
    keywords=[
        "storage layout drift",
        "proxy storage audit",
        "upgrade storage check",
        "storage slot collision",
        "gap compliance",
        "upgradeable storage",
    ],
    agent_class=PiStorageLayoutDrift,
    input_factory=lambda goal, ctx: StorageDriftInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        previous_code=ctx.get("previous_code", ""),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiERC4626VaultGuard",
    keywords=[
        "erc-4626 audit",
        "vault guard",
        "vault compliance",
        "share inflation check",
        "erc4626 scan",
        "vault rounding audit",
        "deposit vault audit",
    ],
    agent_class=PiERC4626VaultGuard,
    input_factory=lambda goal, ctx: VaultGuardInput(
        file_path=ctx.get("file_path", "vault.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiCrossChainBridgeAuditor",
    keywords=[
        "bridge audit",
        "cross-chain audit",
        "bridge security",
        "bridge replay check",
        "chain-id binding",
        "bridge validator audit",
        "message integrity check",
        "bridge nonce check",
    ],
    agent_class=PiCrossChainBridgeAuditor,
    input_factory=lambda goal, ctx: BridgeAuditInput(
        file_path=ctx.get("file_path", "bridge.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiGasGuzzlerDetector",
    keywords=["gas guzzler", "gas limit exhaustion loop", "unbounded loop check", "gas optimization audit"],
    agent_class=PiGasGuzzlerDetector,
    input_factory=lambda goal, ctx: GasGuzzlerInput(
        file_path=ctx.get("file_path", "gas.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiAssemblyLethalWeapons",
    keywords=[
        "inline assembly memory safety",
        "assembly pointer overwrite",
        "yul safe shift check",
        "assembly optimization linter",
    ],
    agent_class=PiAssemblyLethalWeapons,
    input_factory=lambda goal, ctx: AssemblySafetyInput(
        file_path=ctx.get("file_path", "assembly.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLogicGatekeeper",
    keywords=["dead code check", "tautology check", "unreachable code audit", "contract code formatting linter"],
    agent_class=PiLogicGatekeeper,
    input_factory=lambda goal, ctx: LogicGatekeeperInput(
        file_path=ctx.get("file_path", "logic.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiPhishingShield",
    keywords=["msg.sender check", "phishing shield scan", "eip-3009 permit check", "gasless permit verification"],
    agent_class=PiPhishingShield,
    input_factory=lambda goal, ctx: PhishingShieldInput(
        file_path=ctx.get("file_path", "phishing.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiExternalContractGuard",
    keywords=[
        "untrusted contract scan",
        "external dependency verify",
        "ierc interface audit",
        "external call address safety",
    ],
    agent_class=PiExternalContractGuard,
    input_factory=lambda goal, ctx: ExternalContractGuardInput(
        file_path=ctx.get("file_path", "external.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiCentralizationSentry",
    keywords=[
        "centralization risk audit",
        "timelock validator",
        "multisig compliance setup",
        "admin role access checks",
    ],
    agent_class=PiCentralizationSentry,
    input_factory=lambda goal, ctx: CentralizationInput(
        file_path=ctx.get("file_path", "centralization.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiFloatingPragmaSentry",
    keywords=[
        "floating pragma scan",
        "pragma compiler version locked",
        "safe pragma linter",
        "pragma solidity check",
        "floating pragma",
        "pragma solidity",
    ],
    agent_class=PiFloatingPragmaSentry,
    input_factory=lambda goal, ctx: PragmaSentryInput(
        file_path=ctx.get("file_path", "pragma.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiUpgradeDefectDetector",
    keywords=[
        "storage gap gap audit",
        "storage gap audit",
        "storage collision scan",
        "upgradeable state initialize check",
        "uninitialized proxy storage",
        "storage collision",
        "upgrade defect",
    ],
    agent_class=PiUpgradeDefectDetector,
    input_factory=lambda goal, ctx: UpgradeDefectInput(
        file_path=ctx.get("file_path", "upgrade.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiDoSGasLimitsSentry",
    keywords=[
        "dos external call in loop",
        "block gas limit dos",
        "pull over push verifier",
        "batch payment safety check",
        "dos gas limits",
        "block gas limit",
    ],
    agent_class=PiDoSGasLimitsSentry,
    input_factory=lambda goal, ctx: DoSGasLimitsInput(
        file_path=ctx.get("file_path", "dos.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiDeFiSlippageGuard",
    keywords=[
        "zero slippage swap scan",
        "uniswap amountoutmin zero audit",
        "slippage slippage guard verifier",
        "slippage tolerance validator",
        "slippage guard",
        "defi slippage",
    ],
    agent_class=PiDeFiSlippageGuard,
    input_factory=lambda goal, ctx: DeFiSlippageInput(
        file_path=ctx.get("file_path", "slippage.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

# 10 New Specialized Dual-Use PI Agents Registration
AgentRouter.register(
    agent_name="PiReentrancyGuardSpec",
    keywords=[
        "reentrancy guard spec",
        "reentrancy pattern audit",
        "nonreentrant modifier check",
        "checks effects interactions audit",
        "reentrancy spec",
        "reentrancy pattern",
    ],
    agent_class=PiReentrancyGuardSpec,
    input_factory=lambda goal, ctx: ReentrancyGuardSpecInput(
        file_path=ctx.get("file_path", "reentrancy_spec.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiUniswapV3PoolSentry",
    keywords=[
        "uniswap v3 pool price sentry",
        "uniswap slot0 price manipulation",
        "uniswap v3 twap observe",
        "uniswap slot0 risk audit",
        "uniswap v3 pool sentry",
        "uniswap v3",
    ],
    agent_class=PiUniswapV3PoolSentry,
    input_factory=lambda goal, ctx: UniV3SentryInput(
        file_path=ctx.get("file_path", "univ3.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSandwichMEVShield",
    keywords=[
        "sandwich mev shield",
        "amm sandwich frontrun risk",
        "swap exact tokens zero slippage",
        "amm minimum output frontrun",
        "sandwich mev",
        "mev shield",
    ],
    agent_class=PiSandwichMEVShield,
    input_factory=lambda goal, ctx: MEVShieldInput(
        file_path=ctx.get("file_path", "mev_shield.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityCompilerBugsSentry",
    keywords=[
        "solidity compiler bugs sentry",
        "compiler cve memory safety check",
        "yul optimizer storage offset bug",
        "outdated buggy compiler audit",
        "compiler bugs",
        "buggy compiler",
    ],
    agent_class=PiSolidityCompilerBugsSentry,
    input_factory=lambda goal, ctx: CompilerBugsInput(
        file_path=ctx.get("file_path", "compiler_bugs.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiAccessControlShadow",
    keywords=[
        "access control shadow",
        "admin role timelock check",
        "unprotected administrative function",
        "constructor role init compliance",
        "access control shadow",
        "role shadow",
    ],
    agent_class=PiAccessControlShadow,
    input_factory=lambda goal, ctx: ACShadowInput(
        file_path=ctx.get("file_path", "ac_shadow.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLLMHallucinationDetector",
    keywords=[
        "llm hallucination detector",
        "llm self contradiction audit",
        "llm output factuality validation",
        "llm semantic drift checker",
        "hallucination detector",
        "hallucination",
    ],
    agent_class=PiLLMHallucinationDetector,
    input_factory=lambda goal, ctx: HallucinationDetectorInput(
        prompt=ctx.get("prompt", "Analyze this contract."),
        response=ctx.get("response", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiERC20PermitPhishingGuard",
    keywords=[
        "erc20 permit phishing guard",
        "eip-2612 gasless permit audit",
        "permit approval phishing sentry",
        "gasless signature permit safety",
        "permit phishing",
        "permit guard",
    ],
    agent_class=PiERC20PermitPhishingGuard,
    input_factory=lambda goal, ctx: PermitGuardInput(
        file_path=ctx.get("file_path", "permit.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityReentrancyMutexSentry",
    keywords=[
        "reentrancy mutex sentry",
        "custom boolean locked variable check",
        "reentrancy locks gas profile",
        "transient storage tstore mutex",
        "reentrancy mutex",
        "mutex sentry",
    ],
    agent_class=PiSolidityReentrancyMutexSentry,
    input_factory=lambda goal, ctx: MutexSentryInput(
        file_path=ctx.get("file_path", "mutex.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiDeFiMathRoundingSentry",
    keywords=[
        "defi math rounding sentry",
        "integer division rounding check",
        "share conversion inflation audit",
        "defi rounding direction safety",
        "math rounding",
        "rounding sentry",
    ],
    agent_class=PiDeFiMathRoundingSentry,
    input_factory=lambda goal, ctx: MathRoundingInput(
        file_path=ctx.get("file_path", "rounding.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiCrossChainMessageReplaySentry",
    keywords=[
        "cross chain message replay sentry",
        "bridge message deduplication map",
        "bridge receiver replay guard check",
        "bridge replay nonce checker",
        "message replay",
        "bridge replay",
    ],
    agent_class=PiCrossChainMessageReplaySentry,
    input_factory=lambda goal, ctx: BridgeReplayInput(
        file_path=ctx.get("file_path", "replay.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

# 10 Additional Highly Specialized Dual-Use PI Agents Registrations (Agents 11-20)
AgentRouter.register(
    agent_name="PiSolidityTransientStorageSentry",
    keywords=[
        "solidity transient storage sentry",
        "transient storage check",
        "tstore tload safety",
        "cancun transient storage",
        "transient storage",
        "tstore sentry",
    ],
    agent_class=PiSolidityTransientStorageSentry,
    input_factory=lambda goal, ctx: TransientStorageInput(
        file_path=ctx.get("file_path", "transient.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiEIP712SignatureLinter",
    keywords=[
        "eip712 signature linter",
        "eip-712 structured signing linter",
        "domain separator check",
        "signature linter",
        "eip712 verification",
    ],
    agent_class=PiEIP712SignatureLinter,
    input_factory=lambda goal, ctx: EIP712LinterInput(
        file_path=ctx.get("file_path", "eip712.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiReadOnlyOracleManipulationSentry",
    keywords=[
        "read only oracle manipulation sentry",
        "spot balance pricing check",
        "read only reentrancy audit",
        "spot oracle manipulation",
        "read only oracle",
    ],
    agent_class=PiReadOnlyOracleManipulationSentry,
    input_factory=lambda goal, ctx: ReadOnlyOracleInput(
        file_path=ctx.get("file_path", "oracle.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiRustAnchorSecuritySentry",
    keywords=[
        "solana anchor security sentry",
        "anchor rust program audit",
        "solana signer check",
        "anchor security",
        "solana rust sentry",
    ],
    agent_class=PiRustAnchorSecuritySentry,
    input_factory=lambda goal, ctx: AnchorSecurityInput(
        file_path=ctx.get("file_path", "lib.rs"),
        rust_code=ctx.get("rust_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiEIP4337AccountAbstractionSentry",
    keywords=[
        "eip4337 account abstraction sentry",
        "smart account validation audit",
        "paymaster state access check",
        "account abstraction sentry",
        "erc-4337 sentry",
    ],
    agent_class=PiEIP4337AccountAbstractionSentry,
    input_factory=lambda goal, ctx: AccountAbstractionInput(
        file_path=ctx.get("file_path", "wallet.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiZeroKnowledgeCircuitSentry",
    keywords=[
        "zero knowledge circuit sentry",
        "zk circom signal constraint audit",
        "underconstrained signal search",
        "zk circuit sentry",
        "circom linter",
    ],
    agent_class=PiZeroKnowledgeCircuitSentry,
    input_factory=lambda goal, ctx: ZKCircuitInput(
        file_path=ctx.get("file_path", "circuit.circom"),
        circom_code=ctx.get("circom_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiERC7702DelegationGuard",
    keywords=[
        "erc7702 delegation guard",
        "eip-7702 delegation signature audit",
        "eoa contract delegation check",
        "delegation guard",
        "erc-7702 guard",
    ],
    agent_class=PiERC7702DelegationGuard,
    input_factory=lambda goal, ctx: ERC7702Input(
        file_path=ctx.get("file_path", "delegation.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLLMPromptInjectionSentry",
    keywords=[
        "llm prompt injection sentry",
        "llm jailbreak audit",
        "prompt override shield",
        "prompt injection sentry",
        "jailbreak detector",
    ],
    agent_class=PiLLMPromptInjectionSentry,
    input_factory=lambda goal, ctx: PromptInjectionInput(
        prompt=ctx.get("prompt", goal),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiVyperStateLockSentry",
    keywords=[
        "vyper state lock sentry",
        "vyper nonreentrant lock key audit",
        "vyper state mutex check",
        "vyper state lock",
        "vyper lock sentry",
    ],
    agent_class=PiVyperStateLockSentry,
    input_factory=lambda goal, ctx: VyperLockInput(
        file_path=ctx.get("file_path", "contract.vy"),
        vyper_code=ctx.get("vyper_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityUpgradeableInitializerSentry",
    keywords=[
        "solidity upgradeable initializer sentry",
        "constructor disable initializers audit",
        "upgradeable initializer check",
        "initializer sentry",
        "upgrade initialize guard",
    ],
    agent_class=PiSolidityUpgradeableInitializerSentry,
    input_factory=lambda goal, ctx: UpgradeableInitInput(
        file_path=ctx.get("file_path", "upgrade.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiVyperExternalCallSentry",
    keywords=[
        "vyper external call sentry",
        "vyper checks effects interactions",
        "vyper ext_call audit",
        "vyper state modification external call",
        "vyper call sentry",
    ],
    agent_class=PiVyperExternalCallSentry,
    input_factory=lambda goal, ctx: VyperExternalCallInput(
        file_path=ctx.get("file_path", "contract.vy"),
        vyper_code=ctx.get("vyper_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSoliditySignatureMalleabilitySentry",
    keywords=[
        "solidity signature malleability sentry",
        "ecdsa signature malleability check",
        "raw ecrecover audit",
        "signature malleability sentry",
        "malleability guard",
    ],
    agent_class=PiSoliditySignatureMalleabilitySentry,
    input_factory=lambda goal, ctx: SignatureMalleabilityInput(
        file_path=ctx.get("file_path", "signature.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiZKCircomDivisionSentry",
    keywords=[
        "zk circom division sentry",
        "zk circom zero division constraint",
        "circom division guard",
        "circom zero division linter",
        "circom division sentry",
    ],
    agent_class=PiZKCircomDivisionSentry,
    input_factory=lambda goal, ctx: ZKCircomDivisionInput(
        file_path=ctx.get("file_path", "circuit.circom"),
        circom_code=ctx.get("circom_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiEIP712DomainSeparatorSentry",
    keywords=[
        "eip-712 domain separator sentry",
        "upgradeable domain separator check",
        "dynamic domain separator linter",
        "domain separator validation",
        "domain separator sentry",
    ],
    agent_class=PiEIP712DomainSeparatorSentry,
    input_factory=lambda goal, ctx: DomainSeparatorInput(
        file_path=ctx.get("file_path", "eip712_upgrade.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityArbitraryTransferSentry",
    keywords=[
        "solidity arbitrary transfer sentry",
        "user controlled token transfer check",
        "arbitrary erc20 transfer auditor",
        "transfer parameter validation",
        "arbitrary transfer sentry",
    ],
    agent_class=PiSolidityArbitraryTransferSentry,
    input_factory=lambda goal, ctx: ArbitraryTransferInput(
        file_path=ctx.get("file_path", "transfer.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityDelegatecallStorageSentry",
    keywords=[
        "solidity delegatecall storage sentry",
        "proxy storage layout check",
        "eip-1967 storage slot validation",
        "delegatecall implementation target load",
        "delegatecall storage sentry",
    ],
    agent_class=PiSolidityDelegatecallStorageSentry,
    input_factory=lambda goal, ctx: DelegatecallStorageInput(
        file_path=ctx.get("file_path", "proxy.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityOracleLivenessSentry",
    keywords=[
        "solidity oracle liveness sentry",
        "chainlink latestrounddata freshness check",
        "stale price oracle validation",
        "oracle feed liveness auditor",
        "oracle liveness sentry",
    ],
    agent_class=PiSolidityOracleLivenessSentry,
    input_factory=lambda goal, ctx: OracleLivenessInput(
        file_path=ctx.get("file_path", "oracle_feed.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLLMSystemPromptDriftSentry",
    keywords=[
        "llm system prompt drift sentry",
        "instruction override detection",
        "prompt drift multi turn guard",
        "prompt hijack drift sentry",
        "drift sentry",
    ],
    agent_class=PiLLMSystemPromptDriftSentry,
    input_factory=lambda goal, ctx: SystemPromptDriftInput(
        prompt=ctx.get("prompt", goal),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityDirtyMemorySentry",
    keywords=[
        "solidity dirty memory sentry",
        "yul memory allocation safe",
        "inline assembly free memory pointer check",
        "dirty memory overwrite sentry",
        "dirty memory sentry",
    ],
    agent_class=PiSolidityDirtyMemorySentry,
    input_factory=lambda goal, ctx: DirtyMemoryInput(
        file_path=ctx.get("file_path", "memory.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityERC7702CodeSentry",
    keywords=[
        "solidity erc7702 code sentry",
        "eip-7702 delegation target check",
        "delegation contract selfdestruct check",
        "erc-7702 signature target linter",
        "erc7702 code sentry",
    ],
    agent_class=PiSolidityERC7702CodeSentry,
    input_factory=lambda goal, ctx: ERC7702CodeInput(
        file_path=ctx.get("file_path", "delegation_target.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

# Cohort 4 (Agents 31-40) Registrations
AgentRouter.register(
    agent_name="PiSolidityTransientStorageReentrancySentry",
    keywords=[
        "transient storage reentrancy sentry",
        "transient storage check",
        "tstore clear audit",
        "transient reentrancy linter",
        "transient storage reentrancy",
    ],
    agent_class=PiSolidityTransientStorageReentrancySentry,
    input_factory=lambda goal, ctx: TransientStorageReentrancyInput(
        file_path=ctx.get("file_path", "transient_reentrancy.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityL2GasFeeSentry",
    keywords=[
        "l2 gas fee sentry",
        "l2 calldata fee audit",
        "layer-2 calldata limit",
        "l2 dynamic calldata sentry",
        "l2 gas fee",
    ],
    agent_class=PiSolidityL2GasFeeSentry,
    input_factory=lambda goal, ctx: L2GasFeeInput(
        file_path=ctx.get("file_path", "l2_gas.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiZKCircomUnderconstrainedSentry",
    keywords=[
        "zk circom underconstrained sentry",
        "underconstrained signal check",
        "circom missing constraints",
        "zk constraint linter",
        "circom underconstrained",
    ],
    agent_class=PiZKCircomUnderconstrainedSentry,
    input_factory=lambda goal, ctx: CircomUnderconstrainedInput(
        file_path=ctx.get("file_path", "underconstrained.circom"),
        circom_code=ctx.get("circom_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiRustSolanaReentrancySentry",
    keywords=[
        "rust solana reentrancy sentry",
        "solana duplicate account check",
        "anchor account uniqueness",
        "solana uniqueness sentry",
        "solana accounts check",
    ],
    agent_class=PiRustSolanaReentrancySentry,
    input_factory=lambda goal, ctx: RustSolanaReentrancyInput(
        file_path=ctx.get("file_path", "solana_program.rs"),
        rust_code=ctx.get("rust_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityPriceFeedSequencerSentry",
    keywords=[
        "solidity price feed sequencer sentry",
        "l2 sequencer uptime feed check",
        "stale price sequencer check",
        "price feed sequencer sentry",
        "sequencer uptime sentry",
    ],
    agent_class=PiSolidityPriceFeedSequencerSentry,
    input_factory=lambda goal, ctx: PriceFeedSequencerInput(
        file_path=ctx.get("file_path", "oracle_l2.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityERC20TransferRecipientSentry",
    keywords=[
        "solidity erc20 transfer recipient sentry",
        "safe token destination check",
        "address zero transfer sentry",
        "token recipient sentry",
        "transfer recipient sentry",
    ],
    agent_class=PiSolidityERC20TransferRecipientSentry,
    input_factory=lambda goal, ctx: ERC20TransferRecipientInput(
        file_path=ctx.get("file_path", "erc20_transfer.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityEIP712TypehashMismatchSentry",
    keywords=[
        "solidity eip712 typehash mismatch sentry",
        "eip-712 typehash alignment check",
        "signature struct mismatch sentry",
        "typehash alignment sentry",
        "typehash mismatch sentry",
    ],
    agent_class=PiSolidityEIP712TypehashMismatchSentry,
    input_factory=lambda goal, ctx: EIP712TypehashMismatchInput(
        file_path=ctx.get("file_path", "signature_hash.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityCreate2SaltCollisionSentry",
    keywords=[
        "solidity create2 salt collision sentry",
        "predictable create2 salt check",
        "create2 address hijacking sentry",
        "create2 salt collision sentry",
        "predictable salt sentry",
    ],
    agent_class=PiSolidityCreate2SaltCollisionSentry,
    input_factory=lambda goal, ctx: Create2SaltCollisionInput(
        file_path=ctx.get("file_path", "factory_create2.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityArrayLengthSentry",
    keywords=[
        "solidity array length sentry",
        "unbounded array iteration loop",
        "block gas limit array check",
        "array length sentry",
        "unbounded array sentry",
    ],
    agent_class=PiSolidityArrayLengthSentry,
    input_factory=lambda goal, ctx: ArrayLengthInput(
        file_path=ctx.get("file_path", "unbounded_loop.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLLMPromptInjectionNegativeConstraintSentry",
    keywords=[
        "llm prompt injection negative constraint sentry",
        "negative constraint override check",
        "adversarial prompt negation shield",
        "negative constraint sentry",
        "prompt negation sentry",
    ],
    agent_class=PiLLMPromptInjectionNegativeConstraintSentry,
    input_factory=lambda goal, ctx: NegativeConstraintInput(
        prompt=ctx.get("prompt", goal),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

# Cohort 5 (Agents 41-50) Registrations
AgentRouter.register(
    agent_name="PiSolidityDelegateCallToSelfSentry",
    keywords=[
        "solidity delegatecall to self sentry",
        "delegatecall self check",
        "delegatecall to self sentry",
        "self delegatecall audit",
    ],
    agent_class=PiSolidityDelegateCallToSelfSentry,
    input_factory=lambda goal, ctx: DelegateCallSelfInput(
        file_path=ctx.get("file_path", "self_delegatecall.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityBlockTimestampIntervalSentry",
    keywords=[
        "solidity block timestamp interval sentry",
        "block timestamp staking vest check",
        "timestamp claiming interval sentry",
        "block timestamp interval sentry",
        "timestamp interval sentry",
    ],
    agent_class=PiSolidityBlockTimestampIntervalSentry,
    input_factory=lambda goal, ctx: TimestampIntervalInput(
        file_path=ctx.get("file_path", "timestamp_interval.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityAssemblyMemorySafeSentry",
    keywords=[
        "solidity assembly memory safe sentry",
        "yul memory safe allocation check",
        "assembly memory scratchpad audit",
        "assembly memory safe sentry",
        "assembly memory safe",
    ],
    agent_class=PiSolidityAssemblyMemorySafeSentry,
    input_factory=lambda goal, ctx: AssemblyMemorySafeInput(
        file_path=ctx.get("file_path", "memory_safe.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiRustSolanaSignerAssertionSentry",
    keywords=[
        "rust solana signer assertion sentry",
        "solana anchor signer check",
        "solana duplicate account signer",
        "solana signer assertion sentry",
        "solana signer check",
    ],
    agent_class=PiRustSolanaSignerAssertionSentry,
    input_factory=lambda goal, ctx: SolanaSignerAssertionInput(
        file_path=ctx.get("file_path", "anchor_program.rs"),
        rust_code=ctx.get("rust_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiZKCircomShadowSignalSentry",
    keywords=[
        "zk circom shadow signal sentry",
        "circom signal shadowing constraint",
        "circom local var collision",
        "zk circom shadow signal",
        "circom shadow sentry",
    ],
    agent_class=PiZKCircomShadowSignalSentry,
    input_factory=lambda goal, ctx: CircomShadowSignalInput(
        file_path=ctx.get("file_path", "shadow_signal.circom"),
        circom_code=ctx.get("circom_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityPriceFeedFallbackSentry",
    keywords=[
        "solidity price feed fallback sentry",
        "oracle backup twap price check",
        "stale primary price feed fallback",
        "oracle price fallback sentry",
        "price feed fallback sentry",
    ],
    agent_class=PiSolidityPriceFeedFallbackSentry,
    input_factory=lambda goal, ctx: PriceFeedFallbackInput(
        file_path=ctx.get("file_path", "price_oracle.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiVyperStorageLayoutCollisionSentry",
    keywords=[
        "vyper storage layout collision sentry",
        "vyper proxy slot collision",
        "vyper upgrade storage layout shift",
        "vyper storage collision sentry",
        "vyper storage collision",
    ],
    agent_class=PiVyperStorageLayoutCollisionSentry,
    input_factory=lambda goal, ctx: VyperStorageCollisionInput(
        file_path=ctx.get("file_path", "upgradeable.vy"),
        vyper_code=ctx.get("vyper_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLLMPromptInjectionSystemPromptOverrideSentry",
    keywords=[
        "llm prompt injection system prompt override sentry",
        "adversarial system command bypass",
        "ignore system commands bypass shield",
        "system prompt override sentry",
        "prompt override sentry",
    ],
    agent_class=PiLLMPromptInjectionSystemPromptOverrideSentry,
    input_factory=lambda goal, ctx: SystemPromptOverrideInput(
        prompt=ctx.get("prompt", goal),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiDockerComposeSecuritySentry",
    keywords=[
        "docker compose security sentry",
        "docker compose privileged container",
        "docker socket mount security check",
        "docker compose security sentry",
        "docker compose sentry",
    ],
    agent_class=PiDockerComposeSecuritySentry,
    input_factory=lambda goal, ctx: DockerComposeSecurityInput(
        file_path=ctx.get("file_path", "docker-compose.yml"),
        compose_code=ctx.get("compose_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiGitSecretLeakSentry",
    keywords=[
        "git secret leak sentry",
        "repository private key mnemonic scan",
        "high entropy aws Stripe api credential check",
        "git secret leak sentry",
        "secret leak sentry",
    ],
    agent_class=PiGitSecretLeakSentry,
    input_factory=lambda goal, ctx: GitSecretLeakInput(
        file_path=ctx.get("file_path", "config.json"),
        file_content=ctx.get("file_content", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

# Cohort 6 (Agents 51-60) Registrations
AgentRouter.register(
    agent_name="PiRustTuiResourceLimit",
    keywords=[
        "rust tui resource limit",
        "ratatui terminal loop limit check",
        "tui draw resource sentry",
        "rust tui resource limit",
        "tui resource limit",
    ],
    agent_class=PiRustTuiResourceLimit,
    input_factory=lambda goal, ctx: RustTuiResourceLimitInput(
        file_path=ctx.get("file_path", "main.rs"),
        rust_code=ctx.get("rust_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiGrpcProtocolInterceptor",
    keywords=[
        "grpc protocol interceptor",
        "unencrypted grpc channel scan",
        "grpc insecure port warning check",
        "grpc protocol interceptor",
        "grpc interceptor",
    ],
    agent_class=PiGrpcProtocolInterceptor,
    input_factory=lambda goal, ctx: GrpcProtocolInterceptInput(
        file_path=ctx.get("file_path", "service.proto"),
        grpc_code=ctx.get("grpc_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiDeterministicOutputValid",
    keywords=[
        "deterministic output validation",
        "probabilistic output hallucination checker",
        "system prompt leakage detector",
        "deterministic output valid",
        "deterministic validation",
    ],
    agent_class=PiDeterministicOutputValid,
    input_factory=lambda goal, ctx: DeterministicOutputValidInput(
        file_path=ctx.get("file_path", "generated_output.txt"),
        output_content=ctx.get("output_content", ctx.get("content", goal)),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiZeroTrustExecutionDomain",
    keywords=[
        "zero trust execution domain",
        "tmux privilege escape check",
        "sandbox namespace bounds verifier",
        "zero trust execution domain",
        "execution domain sentry",
    ],
    agent_class=PiZeroTrustExecutionDomain,
    input_factory=lambda goal, ctx: ZeroTrustExecDomainInput(
        file_path=ctx.get("file_path", "run_sandbox.sh"),
        domain_code=ctx.get("domain_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityFlashLoanAttack",
    keywords=[
        "solidity flash loan attack",
        "executeoperation sender verify check",
        "defi flash loan reentrancy sentry",
        "solidity flash loan attack",
        "flash loan attack sentry",
    ],
    agent_class=PiSolidityFlashLoanAttack,
    input_factory=lambda goal, ctx: SolidityFlashLoanInput(
        file_path=ctx.get("file_path", "flash_callback.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiZKProofPublicInputVerif",
    keywords=[
        "zk proof public input verif",
        "zk verifier public input check",
        "verifier custom require state constraint",
        "zk proof public input verif",
        "public input verif sentry",
    ],
    agent_class=PiZKProofPublicInputVerif,
    input_factory=lambda goal, ctx: ZKProofPublicInputVerifInput(
        file_path=ctx.get("file_path", "verifier_caller.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiAdversarialEvaluatorSim",
    keywords=[
        "adversarial evaluator sim",
        "jailbreak simulated override detector",
        "logical paradox filter bypass shield",
        "adversarial evaluator sim",
        "adversarial sim sentry",
    ],
    agent_class=PiAdversarialEvaluatorSim,
    input_factory=lambda goal, ctx: AdversarialEvaluatorSimInput(
        prompt=ctx.get("prompt", goal),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiRustTokioDeadlockSentry",
    keywords=[
        "rust tokio deadlock sentry",
        "async sync lock across await check",
        "tokio block_on nested execution sentry",
        "rust tokio deadlock sentry",
        "deadlock sentry",
    ],
    agent_class=PiRustTokioDeadlockSentry,
    input_factory=lambda goal, ctx: RustTokioDeadlockInput(
        file_path=ctx.get("file_path", "concurrency.rs"),
        rust_code=ctx.get("rust_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiApiReverseEngineeredAuth",
    keywords=[
        "api reverse engineered auth",
        "hardcoded bearer token payload check",
        "jwt weakly signed private key sentry",
        "api reverse engineered auth",
        "reverse engineered auth",
    ],
    agent_class=PiApiReverseEngineeredAuth,
    input_factory=lambda goal, ctx: ApiReverseEngineeredAuthInput(
        file_path=ctx.get("file_path", "auth_integration.py"),
        auth_code=ctx.get("auth_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSemanticSchemaRegistry",
    keywords=[
        "semantic schema registry",
        "unstructured json column injection scan",
        "unversioned dynamic schema change linter",
        "semantic schema registry",
        "schema registry sentry",
    ],
    agent_class=PiSemanticSchemaRegistry,
    input_factory=lambda goal, ctx: SemanticSchemaRegistryInput(
        file_path=ctx.get("file_path", "schema_migration.py"),
        schema_code=ctx.get("schema_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)


# Cohort 7 (Agents 61-110) Registrations
AgentRouter.register(
    agent_name="PiSolidityReentrancyGuardOverlapSentry",
    keywords=[
        "reentrancy guard overlap",
        "overlapping reentrancy guard",
        "redundant reentrancy guard",
        "nonreentrant overlap",
    ],
    agent_class=PiSolidityReentrancyGuardOverlapSentry,
    input_factory=lambda goal, ctx: ReentrancyGuardOverlapInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityTxOriginCallCheckSentry",
    keywords=[
        "tx.origin call check",
        "solidity tx.origin phishing check",
        "tx.origin authorization audit",
        "tx.origin call sentry",
    ],
    agent_class=PiSolidityTxOriginCallCheckSentry,
    input_factory=lambda goal, ctx: TxOriginCallCheckInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityArrayLengthMutationSentry",
    keywords=[
        "array length mutation",
        "solidity array length mutation",
        "array storage length overwrite",
        "array length mutation check",
    ],
    agent_class=PiSolidityArrayLengthMutationSentry,
    input_factory=lambda goal, ctx: ArrayLengthMutationInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityExternalContractsReturnCheck",
    keywords=[
        "external contracts return check",
        "missing contract existence check",
        "untrusted external call success check",
        "external contract check",
    ],
    agent_class=PiSolidityExternalContractsReturnCheck,
    input_factory=lambda goal, ctx: ExternalContractsReturnInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityUnboundedLoopsInStateMutation",
    keywords=[
        "unbounded loops in state mutation",
        "state mutation unbounded loop",
        "gas exhaustion state update check",
        "unbounded loop state mutation",
    ],
    agent_class=PiSolidityUnboundedLoopsInStateMutation,
    input_factory=lambda goal, ctx: UnboundedLoopsStateInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityDivideBeforeMultiplyAuditor",
    keywords=[
        "divide before multiply",
        "solidity division multiplication precision",
        "math precision rounding check",
        "divide before multiply auditor",
    ],
    agent_class=PiSolidityDivideBeforeMultiplyAuditor,
    input_factory=lambda goal, ctx: DivideBeforeMultiplyInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityInitializableGapSentry",
    keywords=[
        "initializable storage gap",
        "upgradeable contract storage gap check",
        "missing storage gap sentry",
        "initializable gap sentry",
    ],
    agent_class=PiSolidityInitializableGapSentry,
    input_factory=lambda goal, ctx: InitializableGapInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSoliditySelfdestructCodeEraseSentry",
    keywords=[
        "selfdestruct code erase",
        "selfdestruct logic check",
        "delegatecall selfdestruct check",
        "selfdestruct code erase sentry",
    ],
    agent_class=PiSoliditySelfdestructCodeEraseSentry,
    input_factory=lambda goal, ctx: SelfdestructCodeEraseInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSoliditySignatureOmittedReplaySentry",
    keywords=[
        "signature omitted replay",
        "omitted signature check",
        "missing signature validation replay",
        "signature omitted replay sentry",
    ],
    agent_class=PiSoliditySignatureOmittedReplaySentry,
    input_factory=lambda goal, ctx: SignatureOmittedReplayInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityOwnerTimelockSentry",
    keywords=[
        "owner timelock sentry",
        "admin action timelock check",
        "missing timelock modifier check",
        "owner timelock check",
    ],
    agent_class=PiSolidityOwnerTimelockSentry,
    input_factory=lambda goal, ctx: OwnerTimelockInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityERC20SafeApproveAuditor",
    keywords=["erc20 safe approve", "safeapprove audit", "approve non-zero to non-zero check", "safeapprove check"],
    agent_class=PiSolidityERC20SafeApproveAuditor,
    input_factory=lambda goal, ctx: ERC20SafeApproveInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityUndeclaredReturnVariableSentry",
    keywords=[
        "undeclared return variable",
        "named return variable check",
        "uninitialized return variable sentry",
        "undeclared return check",
    ],
    agent_class=PiSolidityUndeclaredReturnVariableSentry,
    input_factory=lambda goal, ctx: UndeclaredReturnVariableInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityYulMemoryOffsetAudit",
    keywords=[
        "yul memory offset audit",
        "yul mstore offset check",
        "assembly memory offset check",
        "yul memory offset check",
    ],
    agent_class=PiSolidityYulMemoryOffsetAudit,
    input_factory=lambda goal, ctx: YulMemoryOffsetInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityProxyCallTargetCheck",
    keywords=[
        "proxy call target check",
        "upgradeable proxy address validation",
        "implementation address zero check",
        "proxy call target check",
    ],
    agent_class=PiSolidityProxyCallTargetCheck,
    input_factory=lambda goal, ctx: ProxyCallTargetInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSolidityConstantPragmaValidation",
    keywords=[
        "constant pragma validation",
        "exact solidity pragma check",
        "pragma lock version validator",
        "constant pragma validation",
    ],
    agent_class=PiSolidityConstantPragmaValidation,
    input_factory=lambda goal, ctx: ConstantPragmaInput(
        file_path=ctx.get("file_path", "contract.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiRustSolanaAccountDataValidation",
    keywords=[
        "solana account data validation",
        "solana manual account validation check",
        "solana account type verification",
        "account data validation sentry",
    ],
    agent_class=PiRustSolanaAccountDataValidation,
    input_factory=lambda goal, ctx: SolanaAccountDataInput(
        file_path=ctx.get("file_path", "lib.rs"),
        rust_code=ctx.get("rust_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiRustSolanaMissingSignerAssert",
    keywords=[
        "solana missing signer assert",
        "solana signer verify check",
        "anchor missing signer check",
        "missing signer check sentry",
    ],
    agent_class=PiRustSolanaMissingSignerAssert,
    input_factory=lambda goal, ctx: SolanaMissingSignerInput(
        file_path=ctx.get("file_path", "lib.rs"),
        rust_code=ctx.get("rust_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiRustSolanaArithmeticOverflowCheck",
    keywords=[
        "solana arithmetic overflow check",
        "rust math safety overflow",
        "solana checked math verification",
        "solana overflow sentry",
    ],
    agent_class=PiRustSolanaArithmeticOverflowCheck,
    input_factory=lambda goal, ctx: SolanaArithmeticOverflowInput(
        file_path=ctx.get("file_path", "lib.rs"),
        rust_code=ctx.get("rust_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiRustSolanaOwnerVerificationGuard",
    keywords=[
        "solana owner verification guard",
        "solana owner validation check",
        "anchor owner attribute audit",
        "owner verification guard",
    ],
    agent_class=PiRustSolanaOwnerVerificationGuard,
    input_factory=lambda goal, ctx: SolanaOwnerVerificationInput(
        file_path=ctx.get("file_path", "lib.rs"),
        rust_code=ctx.get("rust_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiRustSolanaCPIInstructionSentry",
    keywords=[
        "solana cpi instruction sentry",
        "solana cross program invocation check",
        "cpi program id validation",
        "cpi instruction sentry",
    ],
    agent_class=PiRustSolanaCPIInstructionSentry,
    input_factory=lambda goal, ctx: SolanaCPIInstructionInput(
        file_path=ctx.get("file_path", "lib.rs"),
        rust_code=ctx.get("rust_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiRustSolanaBorshSerializationLeak",
    keywords=[
        "solana borsh serialization leak",
        "solana borsh format check",
        "borsh deserialize struct length leak",
        "borsh serialization leak",
    ],
    agent_class=PiRustSolanaBorshSerializationLeak,
    input_factory=lambda goal, ctx: SolanaBorshLeakInput(
        file_path=ctx.get("file_path", "lib.rs"),
        rust_code=ctx.get("rust_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiRustSolanaReentrancyCrossProgramSentry",
    keywords=[
        "solana reentrancy cross program sentry",
        "solana cpi reentrancy check",
        "solana reentrancy cross program",
        "cpi reentrancy sentry",
    ],
    agent_class=PiRustSolanaReentrancyCrossProgramSentry,
    input_factory=lambda goal, ctx: SolanaReentrancyCrossInput(
        file_path=ctx.get("file_path", "lib.rs"),
        rust_code=ctx.get("rust_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiRustSolanaSysvarClockVerification",
    keywords=[
        "solana sysvar clock verification",
        "solana clock timestamp check",
        "sysvar clock verification sentry",
        "solana clock validator",
    ],
    agent_class=PiRustSolanaSysvarClockVerification,
    input_factory=lambda goal, ctx: SolanaSysvarClockInput(
        file_path=ctx.get("file_path", "lib.rs"),
        rust_code=ctx.get("rust_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiZKSignalUnconstrainedConstraint",
    keywords=[
        "zk signal unconstrained constraint",
        "circom assign without constraint check",
        "unconstrained signal assignment",
        "zk signal unconstrained",
    ],
    agent_class=PiZKSignalUnconstrainedConstraint,
    input_factory=lambda goal, ctx: ZKSignalUnconstrainedInput(
        file_path=ctx.get("file_path", "circuit.circom"),
        circom_code=ctx.get("circom_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiZKDivByZeroConstraintAuditor",
    keywords=[
        "zk division by zero constraint auditor",
        "circom divide by zero signal check",
        "zk zero divisor validation",
        "zk division by zero",
    ],
    agent_class=PiZKDivByZeroConstraintAuditor,
    input_factory=lambda goal, ctx: ZKDivByZeroConstraintInput(
        file_path=ctx.get("file_path", "circuit.circom"),
        circom_code=ctx.get("circom_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiZKSignalShadowingSignalSentry",
    keywords=[
        "zk signal shadowing signal sentry",
        "circom shadow signal check",
        "circom signal collision linter",
        "zk signal shadowing",
    ],
    agent_class=PiZKSignalShadowingSignalSentry,
    input_factory=lambda goal, ctx: ZKSignalShadowingInput(
        file_path=ctx.get("file_path", "circuit.circom"),
        circom_code=ctx.get("circom_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiZKPublicInputLeakageAuditor",
    keywords=[
        "zk public input leakage auditor",
        "zk public input leak check",
        "circom public input validation",
        "zk public input leak",
    ],
    agent_class=PiZKPublicInputLeakageAuditor,
    input_factory=lambda goal, ctx: ZKPublicInputLeakageInput(
        file_path=ctx.get("file_path", "circuit.circom"),
        circom_code=ctx.get("circom_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiZKNonPrimeFieldRangeSentry",
    keywords=[
        "zk non prime field range sentry",
        "circom non prime field boundary",
        "zk field arithmetic check",
        "zk non prime field range",
    ],
    agent_class=PiZKNonPrimeFieldRangeSentry,
    input_factory=lambda goal, ctx: ZKNonPrimeFieldRangeInput(
        file_path=ctx.get("file_path", "circuit.circom"),
        circom_code=ctx.get("circom_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiZKUnusedConstraintVariables",
    keywords=[
        "zk unused constraint variables",
        "circom unused variable audit",
        "zk dead signals linter",
        "zk unused constraint",
    ],
    agent_class=PiZKUnusedConstraintVariables,
    input_factory=lambda goal, ctx: ZKUnusedConstraintInput(
        file_path=ctx.get("file_path", "circuit.circom"),
        circom_code=ctx.get("circom_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiZKProofForgingValidationSentry",
    keywords=[
        "zk proof forging validation sentry",
        "zk verification key validation",
        "zk proof fake check",
        "zk proof forging validation",
    ],
    agent_class=PiZKProofForgingValidationSentry,
    input_factory=lambda goal, ctx: ZKProofForgingValidationInput(
        file_path=ctx.get("file_path", "verifier.sol"),
        solidity_code=ctx.get("solidity_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLLMSystemPromptHijackSentry",
    keywords=[
        "llm system prompt hijack sentry",
        "llm system prompt hijack",
        "system prompt override shield",
        "prompt hijack sentry",
    ],
    agent_class=PiLLMSystemPromptHijackSentry,
    input_factory=lambda goal, ctx: LLMSystemPromptHijackInput(
        prompt=ctx.get("prompt", goal),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLLMPairwiseAdversarialValidator",
    keywords=[
        "llm pairwise adversarial validator",
        "llm pairwise adversarial check",
        "pairwise response validation",
        "pairwise adversarial validator",
    ],
    agent_class=PiLLMPairwiseAdversarialValidator,
    input_factory=lambda goal, ctx: LLMPairwiseAdversarialInput(
        prompt=ctx.get("prompt", goal),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLLMNegativeConstraintEvasion",
    keywords=[
        "llm negative constraint evasion",
        "negative constraints evasion check",
        "llm prompt negation evasion",
        "negative constraint evasion",
    ],
    agent_class=PiLLMNegativeConstraintEvasion,
    input_factory=lambda goal, ctx: LLMNegativeConstraintInput(
        prompt=ctx.get("prompt", goal),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLLMBase64EncodingDeobfuscator",
    keywords=[
        "llm base64 encoding deobfuscator",
        "base64 obfuscated payload check",
        "llm obfuscation bypass sentry",
        "base64 encoding deobfuscator",
    ],
    agent_class=PiLLMBase64EncodingDeobfuscator,
    input_factory=lambda goal, ctx: LLMBase64DeobfuscatorInput(
        prompt=ctx.get("prompt", goal),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLLMChainOfThoughtBypassSentry",
    keywords=[
        "llm chain of thought bypass sentry",
        "cot bypass audit",
        "chain of thought evasion check",
        "cot bypass sentry",
    ],
    agent_class=PiLLMChainOfThoughtBypassSentry,
    input_factory=lambda goal, ctx: LLMChainOfThoughtBypassInput(
        prompt=ctx.get("prompt", goal),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLLMPromptEgressLeakDetector",
    keywords=[
        "llm prompt egress leak detector",
        "egress prompt leakage sentry",
        "prompt data exfiltration check",
        "prompt egress leak detector",
    ],
    agent_class=PiLLMPromptEgressLeakDetector,
    input_factory=lambda goal, ctx: LLMPromptEgressLeakInput(
        prompt=ctx.get("prompt", goal),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLLMContextWindowDriftSentry",
    keywords=[
        "llm context window drift sentry",
        "llm context drift check",
        "context window exfiltration sentry",
        "context window drift sentry",
    ],
    agent_class=PiLLMContextWindowDriftSentry,
    input_factory=lambda goal, ctx: LLMContextWindowDriftInput(
        prompt=ctx.get("prompt", goal),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiLLMRecursiveRefinementJailbreak",
    keywords=[
        "llm recursive refinement jailbreak",
        "recursive refinement audit",
        "multi-turn adversarial jailbreak",
        "recursive refinement jailbreak",
    ],
    agent_class=PiLLMRecursiveRefinementJailbreak,
    input_factory=lambda goal, ctx: LLMRecursiveRefinementInput(
        prompt=ctx.get("prompt", goal),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiDockerSocketPrivilegeSentry",
    keywords=[
        "docker socket privilege sentry",
        "docker.sock permission mount",
        "docker container privilege escape",
        "docker socket privilege",
    ],
    agent_class=PiDockerSocketPrivilegeSentry,
    input_factory=lambda goal, ctx: DockerSocketPrivilegeInput(
        file_path=ctx.get("file_path", "Dockerfile"),
        dockerfile_code=ctx.get("dockerfile_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiKubernetesRootExecutionLinter",
    keywords=[
        "kubernetes root execution linter",
        "k8s runasnonroot validation",
        "k8s securitycontext root check",
        "kubernetes root execution",
    ],
    agent_class=PiKubernetesRootExecutionLinter,
    input_factory=lambda goal, ctx: KubernetesRootExecutionInput(
        file_path=ctx.get("file_path", "pod.yaml"),
        yaml_code=ctx.get("yaml_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiGitSecretEntropyLeakSentry",
    keywords=[
        "git secret entropy leak sentry",
        "git secret entropy scan",
        "high entropy private key audit",
        "git secret entropy leak",
    ],
    agent_class=PiGitSecretEntropyLeakSentry,
    input_factory=lambda goal, ctx: GitSecretEntropyLeakInput(
        file_path=ctx.get("file_path", "secret.json"),
        code_content=ctx.get("code_content", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiDockerComposePortExposureSentry",
    keywords=[
        "docker compose port exposure sentry",
        "docker compose wildcard port exposure",
        "docker compose insecure port map",
        "docker compose port exposure",
    ],
    agent_class=PiDockerComposePortExposureSentry,
    input_factory=lambda goal, ctx: DockerComposePortExposureInput(
        file_path=ctx.get("file_path", "docker-compose.yml"),
        compose_code=ctx.get("compose_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiGithubActionsUnpinnedVersion",
    keywords=[
        "github actions unpinned version",
        "github actions third-party hash check",
        "github actions commit sha pin",
        "github actions unpinned version",
    ],
    agent_class=PiGithubActionsUnpinnedVersion,
    input_factory=lambda goal, ctx: GithubActionsUnpinnedInput(
        file_path=ctx.get("file_path", "workflow.yaml"),
        yaml_code=ctx.get("yaml_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiTerraformStateCredentialSentry",
    keywords=[
        "terraform state credential sentry",
        "terraform state secret leak",
        "terraform plaintext credentials",
        "terraform state credential",
    ],
    agent_class=PiTerraformStateCredentialSentry,
    input_factory=lambda goal, ctx: TerraformStateCredentialInput(
        file_path=ctx.get("file_path", "main.tf"),
        tf_code=ctx.get("tf_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiNginxReverseProxyHeaderSentry",
    keywords=[
        "nginx reverse proxy header sentry",
        "nginx custom headers safety",
        "nginx forward proxy check",
        "nginx reverse proxy header",
    ],
    agent_class=PiNginxReverseProxyHeaderSentry,
    input_factory=lambda goal, ctx: NginxReverseProxyHeaderInput(
        file_path=ctx.get("file_path", "nginx.conf"),
        nginx_code=ctx.get("nginx_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiDatabaseMigrationUnindexedSentry",
    keywords=[
        "database migration unindexed sentry",
        "unindexed foreign key check",
        "database performance scan",
        "database migration unindexed",
    ],
    agent_class=PiDatabaseMigrationUnindexedSentry,
    input_factory=lambda goal, ctx: DatabaseMigrationUnindexedInput(
        file_path=ctx.get("file_path", "migration.sql"),
        migration_code=ctx.get("migration_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiApiAuthJWTNoneAlgorithmSentry",
    keywords=[
        "api auth jwt none algorithm sentry",
        "jwt algorithm none check",
        "insecure jwt signature override",
        "jwt none algorithm sentry",
    ],
    agent_class=PiApiAuthJWTNoneAlgorithmSentry,
    input_factory=lambda goal, ctx: ApiAuthJWTNoneAlgorithmInput(
        file_path=ctx.get("file_path", "auth.py"),
        code_content=ctx.get("code_content", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiSemanticSchemaDynamicFieldCheck",
    keywords=[
        "semantic schema dynamic field check",
        "json schema injection check",
        "unstructured JSON field validation",
        "semantic schema dynamic field",
    ],
    agent_class=PiSemanticSchemaDynamicFieldCheck,
    input_factory=lambda goal, ctx: SemanticSchemaDynamicFieldInput(
        file_path=ctx.get("file_path", "schema.py"),
        schema_code=ctx.get("schema_code", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiApiAuthHardcodedTokenSentry",
    keywords=[
        "api auth hardcoded token sentry",
        "api hardcoded bearer token check",
        "insecure api password scan",
        "api auth hardcoded token",
    ],
    agent_class=PiApiAuthHardcodedTokenSentry,
    input_factory=lambda goal, ctx: ApiAuthHardcodedTokenInput(
        file_path=ctx.get("file_path", "api.py"),
        code_content=ctx.get("code_content", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)

AgentRouter.register(
    agent_name="PiGrpcWireProtocolInsecureSentry",
    keywords=[
        "grpc wire protocol insecure sentry",
        "grpc wire format encrypt check",
        "grpc plaintext connection sentry",
        "grpc wire protocol insecure",
    ],
    agent_class=PiGrpcWireProtocolInsecureSentry,
    input_factory=lambda goal, ctx: GrpcWireProtocolInsecureInput(
        file_path=ctx.get("file_path", "service.proto"),
        code_content=ctx.get("code_content", ctx.get("content", "")),
        check_level=ctx.get("check_level", "STRICT"),
    ),
)


# Adopted Skills Agents
AgentRouter.register(
    agent_name="PiConstantTimeAuditor",
    keywords=[
        "constant-time",
        "timing side-channel",
        "cryptographic constant time",
        "timing attack check",
        "constant time auditor",
    ],
    agent_class=PiConstantTimeAuditor,
    input_factory=lambda goal, ctx: ConstantTimeInput(
        file_path=ctx.get("file_path", "crypto.py"),
        source_code=ctx.get("source_code", ctx.get("content", "")),
        secrets_context=ctx.get("secrets_context", []),
    ),
)

AgentRouter.register(
    agent_name="PiMemoryZeroizeSentry",
    keywords=[
        "memory zeroize",
        "secret wiping sentry",
        "zeroize buffer",
        "memset security scan",
        "memory zeroize sentry",
    ],
    agent_class=PiMemoryZeroizeSentry,
    input_factory=lambda goal, ctx: MemoryZeroizeInput(
        file_path=ctx.get("file_path", "sec_buffer.c"),
        source_code=ctx.get("source_code", ctx.get("content", "")),
        sensitive_symbols=ctx.get("sensitive_symbols", []),
    ),
)

AgentRouter.register(
    agent_name="PiDimensionalAnalysisSentry",
    keywords=[
        "dimensional analysis",
        "unit mismatch sentry",
        "wei gwei check",
        "currency unit validation",
        "dimensional analysis sentry",
    ],
    agent_class=PiDimensionalAnalysisSentry,
    input_factory=lambda goal, ctx: DimensionalAnalysisInput(
        file_path=ctx.get("file_path", "finance.py"),
        source_code=ctx.get("source_code", ctx.get("content", "")),
        unit_registry=ctx.get("unit_registry", {}),
    ),
)

AgentRouter.register(
    agent_name="PiAgentToolExecutionGuard",
    keywords=[
        "agent tool guard",
        "command runner protection",
        "uncontrolled tool execution",
        "terminal execution guard",
        "agent tool execution guard",
    ],
    agent_class=PiAgentToolExecutionGuard,
    input_factory=lambda goal, ctx: AgentToolGuardInput(
        command_string=ctx.get("command_string", ctx.get("command", goal)),
        allowed_commands=ctx.get("allowed_commands", ["git", "pytest", "ruff", "python"]),
    ),
)

AgentRouter.register(
    agent_name="PiHotPathAllocationAuditor",
    keywords=[
        "hot-path allocation",
        "performance allocation linter",
        "hot path allocation auditor",
        "string allocation performance",
        "hot path linter",
    ],
    agent_class=PiHotPathAllocationAuditor,
    input_factory=lambda goal, ctx: HotPathAllocationInput(
        file_path=ctx.get("file_path", "program.cs"),
        source_code=ctx.get("source_code", ctx.get("content", "")),
        hot_path_lines=ctx.get("hot_path_lines", []),
    ),
)

AgentRouter.register(
    agent_name="PiCavemanTokenCompressor",
    keywords=[
        "caveman compress",
        "token compression",
        "prompt compression",
        "conversational fluff",
        "caveman token compressor",
    ],
    agent_class=PiCavemanTokenCompressor,
    input_factory=lambda goal, ctx: CavemanCompressorInput(
        text_payload=ctx.get("text_payload", ctx.get("text", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiGrillMeQuestionnaire",
    keywords=["grill me questionnaire", "design plan audit", "grill plan", "vague plan", "grill me"],
    agent_class=PiGrillMeQuestionnaire,
    input_factory=lambda goal, ctx: GrillMeInput(
        plan_content=ctx.get("plan_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiHandoffCheckpointSentry",
    keywords=[
        "handoff sentry",
        "handoff checkpoint",
        "reproduction script check",
        "handoff verify",
        "handoff checkpoint sentry",
    ],
    agent_class=PiHandoffCheckpointSentry,
    input_factory=lambda goal, ctx: HandoffInput(
        handoff_content=ctx.get("handoff_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiToPrdValidator",
    keywords=["prd validator", "prd spec verify", "prd layout", "objectives specifications", "to prd validator"],
    agent_class=PiToPrdValidator,
    input_factory=lambda goal, ctx: ToPrdInput(
        prd_content=ctx.get("prd_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiToIssuesBreakdown",
    keywords=[
        "issues breakdown",
        "task list parser",
        "acceptance criteria verify",
        "checklist parsing",
        "to issues breakdown",
    ],
    agent_class=PiToIssuesBreakdown,
    input_factory=lambda goal, ctx: ToIssuesInput(
        spec_content=ctx.get("spec_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiTriageBugLabels",
    keywords=["triage bug", "stack trace classification", "bug labels", "severity classification", "triage bug labels"],
    agent_class=PiTriageBugLabels,
    input_factory=lambda goal, ctx: TriageInput(
        log_content=ctx.get("log_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiZoomOutSystemExplainer",
    keywords=[
        "zoom out explainer",
        "system architecture explainer",
        "imports map diagram",
        "dependency diagram",
        "zoom out system explainer",
    ],
    agent_class=PiZoomOutSystemExplainer,
    input_factory=lambda goal, ctx: ZoomOutInput(
        file_path=ctx.get("file_path", "app.py"),
        code_content=ctx.get("code_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiDesignAnInterfaceValidator",
    keywords=[
        "design interface",
        "interface docstrings",
        "typed variables interface",
        "strict return types",
        "design an interface validator",
    ],
    agent_class=PiDesignAnInterfaceValidator,
    input_factory=lambda goal, ctx: DesignAnInterfaceInput(
        interface_content=ctx.get("interface_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiRequestRefactorPlanVerifier",
    keywords=[
        "refactor plan",
        "migration safety checkpoints",
        "dependency maps",
        "refactoring verifier",
        "request refactor plan verifier",
    ],
    agent_class=PiRequestRefactorPlanVerifier,
    input_factory=lambda goal, ctx: RequestRefactorInput(
        plan_content=ctx.get("plan_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiTddTestFileVerifier",
    keywords=[
        "tdd file verifier",
        "test file matching",
        "production test pairing",
        "changeset test verification",
        "tdd test file verifier",
    ],
    agent_class=PiTddTestFileVerifier,
    input_factory=lambda goal, ctx: TddTestFileInput(
        modified_files=ctx.get("modified_files", [ctx.get("file_path", "main.py")]),
    ),
)

AgentRouter.register(
    agent_name="PiTddAssertionCoverage",
    keywords=[
        "tdd assertion coverage",
        "missing assertions check",
        "test method assert check",
        "test verification coverage",
        "tdd assertion coverage",
    ],
    agent_class=PiTddAssertionCoverage,
    input_factory=lambda goal, ctx: TddAssertionInput(
        test_code_content=ctx.get("test_code_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiTddMockingSanityChecker",
    keywords=[
        "tdd mocking sanity",
        "unsafe mock check",
        "mock interface validator",
        "excessive mocking detector",
        "tdd mocking sanity checker",
    ],
    agent_class=PiTddMockingSanityChecker,
    input_factory=lambda goal, ctx: TddMockingInput(
        test_code_content=ctx.get("test_code_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiGitSafetyGuardrail",
    keywords=["git safety guardrail", "unsafe git command", "force push block", "branch deletion check", "git safety"],
    agent_class=PiGitSafetyGuardrail,
    input_factory=lambda goal, ctx: GitSafetyInput(
        command_string=ctx.get("command_string", ctx.get("command", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiTypeScriptWizardryCheck",
    keywords=[
        "typescript wizardry",
        "typescript any check",
        "as any typescript linter",
        "typescript return type verify",
        "typescript wizardry check",
    ],
    agent_class=PiTypeScriptWizardryCheck,
    input_factory=lambda goal, ctx: TypeScriptWizardryInput(
        code_content=ctx.get("code_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiArchitectureImportBoundarySentry",
    keywords=[
        "architecture import boundary",
        "import boundary sentry",
        "cross layer violation",
        "import mapping block",
        "architecture import boundary sentry",
    ],
    agent_class=PiArchitectureImportBoundarySentry,
    input_factory=lambda goal, ctx: ImportBoundaryInput(
        file_path=ctx.get("file_path", "domain/user.py"),
        code_content=ctx.get("code_content", ctx.get("content", goal)),
        forbidden_mappings=ctx.get("forbidden_mappings", {}),
    ),
)

AgentRouter.register(
    agent_name="PiDepreciationScanner",
    keywords=[
        "depreciation scanner",
        "deprecated library scan",
        "deprecated pattern",
        "obsolete modules",
        "depreciation scanner",
    ],
    agent_class=PiDepreciationScanner,
    input_factory=lambda goal, ctx: DepreciationInput(
        file_path=ctx.get("file_path", "program.py"),
        code_content=ctx.get("code_content", ctx.get("content", goal)),
        deprecated_patterns=ctx.get("deprecated_patterns", []),
    ),
)

AgentRouter.register(
    agent_name="PiDeadCodePruner",
    keywords=[
        "dead code pruner",
        "unused private variable",
        "unused import scanner",
        "dead return path",
        "dead code pruner",
    ],
    agent_class=PiDeadCodePruner,
    input_factory=lambda goal, ctx: DeadCodeInput(
        file_path=ctx.get("file_path", "program.py"),
        code_content=ctx.get("code_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiMockDataTaintingSentry",
    keywords=[
        "mock data tainting",
        "mock tainting sentry",
        "high entropy credentials",
        "mock server ips check",
        "mock data tainting sentry",
    ],
    agent_class=PiMockDataTaintingSentry,
    input_factory=lambda goal, ctx: MockDataTaintingInput(
        file_path=ctx.get("file_path", "mocks.json"),
        data_content=ctx.get("data_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiReadmeValidator",
    keywords=[
        "readme validator",
        "readme installation check",
        "setup variables documentation",
        "readme layout check",
        "readme validator",
    ],
    agent_class=PiReadmeValidator,
    input_factory=lambda goal, ctx: ReadmeInput(
        readme_content=ctx.get("readme_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiChangelogAuditor",
    keywords=[
        "changelog auditor",
        "changelog version verify",
        "changelog structure",
        "release version auditor",
        "changelog auditor",
    ],
    agent_class=PiChangelogAuditor,
    input_factory=lambda goal, ctx: ChangelogInput(
        changelog_content=ctx.get("changelog_content", ctx.get("content", goal)),
        target_version=ctx.get("target_version", "1.0.0"),
    ),
)

AgentRouter.register(
    agent_name="PiAstDepthGuard",
    keywords=[
        "ast depth guard",
        "nesting complexity linter",
        "ast depth threshold",
        "ast complexity guard",
        "ast depth guard",
    ],
    agent_class=PiAstDepthGuard,
    input_factory=lambda goal, ctx: AstDepthInput(
        file_path=ctx.get("file_path", "main.py"),
        code_content=ctx.get("code_content", ctx.get("content", goal)),
        max_depth=ctx.get("max_depth", 5),
    ),
)

AgentRouter.register(
    agent_name="PiUncontrolledRecursionSentry",
    keywords=[
        "uncontrolled recursion",
        "recursion base case",
        "infinite recursion scanner",
        "recursion exit branch",
        "uncontrolled recursion sentry",
    ],
    agent_class=PiUncontrolledRecursionSentry,
    input_factory=lambda goal, ctx: RecursionInput(
        file_path=ctx.get("file_path", "recursion.py"),
        code_content=ctx.get("code_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiMagicNumberScanner",
    keywords=[
        "magic number scanner",
        "hardcoded numeric constant",
        "business computations check",
        "magical constant scanner",
        "magic number scanner",
    ],
    agent_class=PiMagicNumberScanner,
    input_factory=lambda goal, ctx: MagicNumberInput(
        file_path=ctx.get("file_path", "calc.py"),
        code_content=ctx.get("code_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiErrorHandlingCatchAllGuard",
    keywords=[
        "error handling catch-all",
        "silent swallow exception",
        "try-except catch-all",
        "missing raise exception",
        "error handling catch all guard",
    ],
    agent_class=PiErrorHandlingCatchAllGuard,
    input_factory=lambda goal, ctx: ErrorCatchInput(
        file_path=ctx.get("file_path", "handler.py"),
        code_content=ctx.get("code_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiSemanticCommitMessageLinter",
    keywords=[
        "semantic commit message",
        "conventional commit linter",
        "commit structure",
        "git message audit",
        "semantic commit message linter",
    ],
    agent_class=PiSemanticCommitMessageLinter,
    input_factory=lambda goal, ctx: CommitLinterInput(
        commit_message=ctx.get("commit_message", ctx.get("message", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiWebVulnScanner",
    keywords=["web vuln scanner", "xss check", "csrf check", "csp configuration", "web vulnerability scan"],
    agent_class=PiWebVulnScanner,
    input_factory=lambda goal, ctx: WebVulnInput(
        file_path=ctx.get("file_path", "index.html"),
        code_content=ctx.get("code_content", ctx.get("content", goal)),
    ),
)

AgentRouter.register(
    agent_name="PiDeploymentSafetyGuard",
    keywords=["deployment safety", "safe deployment", "rollback gates", "post-remediation deploy"],
    agent_class=PiDeploymentSafetyGuard,
    input_factory=lambda goal, ctx: DeploymentSafetyInput(
        deployment_target=ctx.get("deployment_target", "production"),
        post_remediation_code=ctx.get("post_remediation_code", ctx.get("content", goal)),
        health_check_endpoint=ctx.get("health_check_endpoint", "http://localhost:8080/health"),
    ),
)

AgentRouter.register(
    agent_name="PiPipelineIntegrityAuditor",
    keywords=["pipeline integrity", "cicd auditor", "workflow safety", "action injection"],
    agent_class=PiPipelineIntegrityAuditor,
    input_factory=lambda goal, ctx: PipelineIntegrityInput(
        workflow_path=ctx.get("workflow_path", "release.yml"),
        workflow_content=ctx.get("workflow_content", ctx.get("content", goal)),
    ),
)


# ==============================================================================
# Playbooks Phase 2-4 Integration Placeholder/Stub Registrations
# These stubs allow AgentChainCompiler to successfully compile the 20 new playbooks.
# ==============================================================================


class GenericStubInput(BaseModel):
    goal: str = ""
    content: str = ""


class GenericStubAgent:
    def __init__(self, agent_name: str = "GenericStub") -> None:
        self.agent_name = agent_name

    def execute(self, input_envelope: GenericStubInput) -> Any:
        return {"is_secure": True, "success": True}


# Cloud Cost Playbook
AgentRouter.register(
    agent_name="PiCloudCostAnalyzer",
    keywords=["cloud cost", "cost analyzer", "spend metrics", "cloud spend"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiIdleResourceSentry",
    keywords=["idle resource", "resource leaks", "idle instance", "unused volume"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiBudgetAnomalyGuard",
    keywords=["budget anomaly", "anomaly guard", "cost spike", "spend anomaly"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)

# API Security Playbook
AgentRouter.register(
    agent_name="PiAPIRateLimitSentry",
    keywords=["api rate limit", "rate limiting", "rate limit sentry", "rate limiter"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiEndpointAbuseGuard",
    keywords=["endpoint abuse", "abuse guard", "api abuse", "endpoint protection"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)

# Database Query Optimization Playbook
AgentRouter.register(
    agent_name="PiSlowQueryDetector",
    keywords=["slow query", "slow query detector", "query latency", "db latency"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiSQLInjectionSentry",
    keywords=["sql injection", "sqli check", "injection sentry", "sql vulnerability"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiIndexRecommendationEngine",
    keywords=["index recommendation", "index recommendation engine", "missing index", "db indexing"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)

# Container Image Security Playbook
AgentRouter.register(
    agent_name="PiDockerImageScanner",
    keywords=["docker image scanner", "image scan", "container image vuln", "base image vulnerability"],
    agent_class=PiDockerImageScanner,
    input_factory=lambda goal, ctx: DockerImageInput(
        file_path=ctx.get("file_path", "Dockerfile"),
        dockerfile_content=ctx.get("dockerfile_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiContainerEscapeDetector",
    keywords=["container escape", "escape detector", "privilege escalation container", "runtime jailbreak"],
    agent_class=PiContainerEscapeDetector,
    input_factory=lambda goal, ctx: ContainerEscapeInput(
        file_path=ctx.get("file_path", "deployment.yaml"),
        config_content=ctx.get("config_content", ctx.get("content", goal)),
    ),
)

# Frontend Supply Chain Playbook
AgentRouter.register(
    agent_name="PiNPMDependencyVulnScanner",
    keywords=["npm dependency", "npm audit", "npm vuln scanner", "frontend supply chain"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiTreeShakingOptimizer",
    keywords=["tree shaking", "bundle optimization", "tree shaking optimizer", "unused exports"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)

# LLM Output Sanitization Playbook
AgentRouter.register(
    agent_name="PiLLMOutputSanitizer",
    keywords=["llm output", "output sanitizer", "egress filter llm", "response sanitization"],
    agent_class=PiLLMOutputSanitizer,
    input_factory=lambda goal, ctx: LLMOutputSanitizerInput(
        raw_output=ctx.get("raw_output", ctx.get("content", goal)),
        system_prompt_reference=ctx.get("system_prompt_reference", ""),
    ),
)

# Data Privacy Compliance Playbook
AgentRouter.register(
    agent_name="PiDataFlowPrivacyMapper",
    keywords=["data flow privacy", "privacy mapper", "pii tracking", "data lifecycle mapping"],
    agent_class=PiDataFlowPrivacyMapper,
    input_factory=lambda goal, ctx: PrivacyMapperInput(
        data_sources=ctx.get("data_sources", ["email", "ssn"]),
        data_destinations=ctx.get("data_destinations", ["public_endpoint", "stdout"]),
        flow_connections=ctx.get("flow_connections", [{"from": "email", "to": "public_endpoint"}]),
    ),
)
AgentRouter.register(
    agent_name="PiSensitiveDataScanner",
    keywords=["sensitive data scanner", "pii detector", "sensitive field", "credit card scanner"],
    agent_class=PiSensitiveDataScanner,
    input_factory=lambda goal, ctx: SensitiveDataInput(
        data_label=ctx.get("data_label", "input_stream"),
        text_content=ctx.get("text_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiAutomatedAnonymizer",
    keywords=["automated anonymizer", "data masking", "pii redaction", "anonymization engine"],
    agent_class=PiAutomatedAnonymizer,
    input_factory=lambda goal, ctx: AnonymizerInput(
        raw_payload=ctx.get("raw_payload", ctx.get("content", goal)),
        mask_character=ctx.get("mask_character", "*"),
        hash_salt=ctx.get("hash_salt", "pi_salt"),
    ),
)

# Logging & Observability Playbook
AgentRouter.register(
    agent_name="PiSensitiveLogLeakSentry",
    keywords=["sensitive log leak", "log leak sentry", "pii log scanner", "log credential scan"],
    agent_class=PiSensitiveLogLeakSentry,
    input_factory=lambda goal, ctx: LogLeakInput(
        log_file_path=ctx.get("log_file_path", "app.log"),
        log_content=ctx.get("log_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiStructuredLoggingEnforcer",
    keywords=["structured logging", "logging enforcer", "json logger", "log formatting audit"],
    agent_class=PiStructuredLoggingEnforcer,
    input_factory=lambda goal, ctx: StructuredLoggingInput(
        file_path=ctx.get("file_path", "logger.py"),
        code_content=ctx.get("code_content", ctx.get("content", goal)),
    ),
)

# Access Control Playbook
AgentRouter.register(
    agent_name="PiIAMOverPermissionSentry",
    keywords=["iam over permission", "iam permissions", "excessive iam", "cloud policy audit"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiLeastPrivilegeRemediator",
    keywords=[
        "least privilege remediator",
        "least privilege auto-remediation",
        "revoke permissions",
        "policy hardening",
    ],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)

# Documentation Playbook
AgentRouter.register(
    agent_name="PiDocsOutdatedChecker",
    keywords=["docs outdated checker", "stale documentation", "outdated README", "docs check"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiAutoDocsGenerator",
    keywords=["auto docs generator", "inline comments generator", "docstring updater", "autodoc"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)

# Performance Profiling Playbook
AgentRouter.register(
    agent_name="PiMemoryLeakDetector",
    keywords=["memory leak detector", "valgrind profile", "leak analysis", "heap profile"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiBottleneckOptimizer",
    keywords=["bottleneck optimizer", "profiling optimizer", "hot-spot refactoring", "performance bypass"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)

# Mobile App Playbook
AgentRouter.register(
    agent_name="PiMobilePermissionSentry",
    keywords=["mobile permission sentry", "ios permission audit", "android manifest audit", "mobile permission sentry"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiAppDataLeakDetector",
    keywords=["app data leak", "mobile data leak detector", "local storage plain text", "insecure mobile sandbox"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiRuntimeHardeningGuard",
    keywords=["runtime hardening", "jailbreak detection", "root detection", "anti-tamper runtime"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)

# Network Traffic Playbook
AgentRouter.register(
    agent_name="PiNetworkTrafficSentry",
    keywords=["network traffic sentry", "packet inspector", "unencrypted endpoints", "cleartext traffic"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiDDoSPatternDetector",
    keywords=["ddos pattern detector", "rate flood patterns", "syn flood detection", "traffic anomaly detector"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiTrafficOptimizer",
    keywords=["traffic optimizer", "bandwidth optimization", "cdn route analyzer", "payload compression analyzer"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)

# Backup & Disaster Recovery Playbook
AgentRouter.register(
    agent_name="PiBackupIntegritySentry",
    keywords=["backup integrity sentry", "corrupted backups", "snapshot validation", "backup recovery check"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiRecoveryTimeAuditor",
    keywords=["recovery time auditor", "rto/rpo constraints", "restoration time log", "disaster metrics"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiAutomatedRestoreTester",
    keywords=[
        "automated restore tester",
        "non-disruptive sandbox restore",
        "automated recovery testing",
        "dry-run restoration",
    ],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)

# Accessibility Playbook
AgentRouter.register(
    agent_name="PiAccessibilityScanner",
    keywords=["accessibility scanner", "wcag audit", "aria landmarks scanner", "screen reader check"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiContrastRatioAuditor",
    keywords=[
        "contrast ratio auditor",
        "color contrast verification",
        "low contrast audit",
        "wcag readability standard",
    ],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiAutoRemediationEngine",
    keywords=[
        "auto remediation engine",
        "aria attributes auto-apply",
        "accessibility fixes automagic",
        "accessibility remediation",
    ],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)

# Secrets Management Playbook
AgentRouter.register(
    agent_name="PiHardcodedSecretDetector",
    keywords=[
        "hardcoded secret detector",
        "embedded passwords check",
        "plain credentials scanner",
        "auth secret detector",
    ],
    agent_class=PiHardcodedSecretDetector,
    input_factory=lambda goal, ctx: HardcodedSecretInput(
        file_path=ctx.get("file_path", "secrets_config.py"),
        file_content=ctx.get("file_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiAutomatedRotationEngine",
    keywords=[
        "automated rotation engine",
        "vault credential rotater",
        "kms key rotation automation",
        "secrets auto-rotation",
    ],
    agent_class=PiAutomatedRotationEngine,
    input_factory=lambda goal, ctx: RotationInput(
        credential_type=ctx.get("credential_type", "API_KEY"),
        target_identifier=ctx.get("target_identifier", "default_key"),
        current_value_snippet=ctx.get("current_value_snippet", ""),
    ),
)

# IaC Playbook
AgentRouter.register(
    agent_name="PiTerraformDriftDetector",
    keywords=["terraform drift detector", "iac drift", "resource state discrepancy", "tf state drift"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiInfrastructureComplianceAuditor",
    keywords=[
        "infrastructure compliance auditor",
        "cis benchmark compliance",
        "unencrypted s3 buckets check",
        "iac standards auditor",
    ],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)

# Frontend Core Web Vitals Playbook
AgentRouter.register(
    agent_name="PiLighthouseAuditor",
    keywords=["lighthouse auditor", "performance speed score", "cls/fid audit", "lighthouse simulation"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiBundleSizeSentry",
    keywords=["bundle size sentry", "webpack asset limits", "chunk size audit", "bundle budget check"],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)
AgentRouter.register(
    agent_name="PiCoreWebVitalsOptimizer",
    keywords=[
        "core web vitals optimizer",
        "lcp defer non-critical",
        "image aspect-ratio injector",
        "vitals auto-healing",
    ],
    agent_class=GenericStubAgent,
    input_factory=lambda goal, ctx: GenericStubInput(goal=goal, content=ctx.get("content", "")),
)

# Phase 4 Complementary Micro-Agents Registration
AgentRouter.register(
    agent_name="PiIaCScanner",
    keywords=[
        "iac scanner",
        "terraform security scan",
        "cloudformation audit",
        "pulumi security scanner",
        "s3 bucket exposure",
    ],
    agent_class=PiIaCScanner,
    input_factory=lambda goal, ctx: IaCInput(
        file_path=ctx.get("file_path", "main.tf"),
        iac_content=ctx.get("iac_content", ctx.get("content", goal)),
        iac_type=ctx.get("iac_type", "terraform"),
    ),
)
AgentRouter.register(
    agent_name="PiDependencyVulnScanner",
    keywords=[
        "dependency vuln scanner",
        "known vulnerability check",
        "lockfile vulnerability scanner",
        "lodash CVE check",
        "log4shell scanner",
    ],
    agent_class=PiDependencyVulnScanner,
    input_factory=lambda goal, ctx: DependencyInput(
        lockfile_path=ctx.get("lockfile_path", "package-lock.json"),
        lockfile_content=ctx.get("lockfile_content", ctx.get("content", goal)),
        ecosystem=ctx.get("ecosystem", "npm"),
    ),
)
AgentRouter.register(
    agent_name="PiCloudConfigAuditor",
    keywords=[
        "cloud config auditor",
        "unrestricted security groups check",
        "aws block public access",
        "logging flow logs disabled",
        "gcp default network",
    ],
    agent_class=PiCloudConfigAuditor,
    input_factory=lambda goal, ctx: CloudConfigInput(
        file_path=ctx.get("file_path", "cloud_config.yaml"),
        config_content=ctx.get("config_content", ctx.get("content", goal)),
        provider=ctx.get("provider", "aws"),
    ),
)
AgentRouter.register(
    agent_name="PiRBACPermissionMapper",
    keywords=[
        "rbac permission mapper",
        "least privilege checker",
        "iam policy auditor",
        "privilege escalation risk",
        "wildcard iam policy check",
    ],
    agent_class=PiRBACPermissionMapper,
    input_factory=lambda goal, ctx: RBACInput(
        policy_file_path=ctx.get("policy_file_path", "policy.json"),
        policy_content=ctx.get("policy_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiEncryptionComplianceChecker",
    keywords=[
        "encryption compliance checker",
        "ssl/tls protocol checker",
        "weak cryptographic algorithm",
        "data-at-rest encryption checker",
    ],
    agent_class=PiEncryptionComplianceChecker,
    input_factory=lambda goal, ctx: EncryptionInput(
        resource_type=ctx.get("resource_type", "database"),
        config_snippet=ctx.get("config_snippet", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiSBOMValidator",
    keywords=[
        "sbom validator",
        "license compliance check",
        "cyclonedx validation",
        "spdx license compliance",
        "copyleft agpl scanner",
    ],
    agent_class=PiSBOMValidator,
    input_factory=lambda goal, ctx: SBOMInput(
        sbom_path=ctx.get("sbom_path", "bom.json"),
        sbom_content=ctx.get("sbom_content", ctx.get("content", goal)),
        format=ctx.get("format", "cyclonedx"),
    ),
)
AgentRouter.register(
    agent_name="PiSupplyChainIntegrityChecker",
    keywords=[
        "supply chain integrity checker",
        "typosquatted dependency checker",
        "package.json typosquatting check",
        "boto4 security check",
        "unpinned dependency checker",
    ],
    agent_class=PiSupplyChainIntegrityChecker,
    input_factory=lambda goal, ctx: SupplyChainInput(
        manifest_path=ctx.get("manifest_path", "package.json"),
        manifest_content=ctx.get("manifest_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiAPIOWASPScanner",
    keywords=[
        "api owasp scanner",
        "openapi schema scanner",
        "broken authentication endpoint",
        "unrestricted resource consumption check",
        "bola vulnerability scan",
    ],
    agent_class=PiAPIOWASPScanner,
    input_factory=lambda goal, ctx: APIInput(
        api_path=ctx.get("api_path", "openapi.yaml"),
        schema_content=ctx.get("schema_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiKubernetesSecurityAuditor",
    keywords=[
        "kubernetes security auditor",
        "privileged k8s container",
        "kubernetes resource limits check",
        "default namespace k8s audit",
        "hostpath volume share",
    ],
    agent_class=PiKubernetesSecurityAuditor,
    input_factory=lambda goal, ctx: K8sInput(
        k8s_content=ctx.get("k8s_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiZeroTrustVerifier",
    keywords=[
        "zero trust verifier",
        "network policy verification",
        "insecure communication protocol transit",
        "mutual tls verification",
        "wildcard ingress rules",
    ],
    agent_class=PiZeroTrustVerifier,
    input_factory=lambda goal, ctx: ZeroTrustInput(
        network_policy_content=ctx.get("network_policy_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiCertificateRotationWatcher",
    keywords=[
        "certificate rotation watcher",
        "self-signed certificate checker",
        "weak key strength watch",
        "certificate expiring check",
    ],
    agent_class=PiCertificateRotationWatcher,
    input_factory=lambda goal, ctx: CertInput(
        cert_content=ctx.get("cert_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiFirewallRuleAuditor",
    keywords=[
        "firewall rule auditor",
        "exposed ssh port check",
        "exposed rdp port check",
        "exposed mongodb port audit",
    ],
    agent_class=PiFirewallRuleAuditor,
    input_factory=lambda goal, ctx: FirewallInput(
        rules_content=ctx.get("rules_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiBackupIntegrityChecker",
    keywords=[
        "backup integrity checker",
        "unencrypted backup check",
        "single point backup failure",
        "short backup retention checker",
    ],
    agent_class=PiBackupIntegrityChecker,
    input_factory=lambda goal, ctx: BackupInput(
        backup_config=ctx.get("backup_config", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiAuditLogTamperDetector",
    keywords=[
        "audit log tamper detector",
        "missing log sequence check",
        "truncate log action check",
        "unauthorized log deletion audit",
    ],
    agent_class=PiAuditLogTamperDetector,
    input_factory=lambda goal, ctx: LogInput(
        log_content=ctx.get("log_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiMisconfigPatternMatcher",
    keywords=[
        "misconfig pattern matcher",
        "hardcoded admin credentials check",
        "debug mode production check",
        "empty db password config",
    ],
    agent_class=PiMisconfigPatternMatcher,
    input_factory=lambda goal, ctx: ConfigInput(
        config_content=ctx.get("config_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiThreatModelGenerator",
    keywords=[
        "threat model generator",
        "stride threat analysis",
        "api security threat mapping",
        "database threat scenarios stride",
    ],
    agent_class=PiThreatModelGenerator,
    input_factory=lambda goal, ctx: SystemInput(
        system_desc=ctx.get("system_desc", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiSecretsManagerCompletenessChecker",
    keywords=[
        "secrets manager completeness checker",
        "missing secrets auto-rotation",
        "wildcard secrets permissions",
        "default kms encryption key",
    ],
    agent_class=PiSecretsManagerCompletenessChecker,
    input_factory=lambda goal, ctx: VaultInput(
        vault_config=ctx.get("vault_config", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiCodeSigningEnforcer",
    keywords=[
        "code signing enforcer",
        "unsigned build artifact audit",
        "expired signing certificate",
        "missing build integrity checksum",
    ],
    agent_class=PiCodeSigningEnforcer,
    input_factory=lambda goal, ctx: ArtifactInput(
        artifact_metadata=ctx.get("artifact_metadata", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiDataRetentionPolicyEnforcer",
    keywords=[
        "data retention policy enforcer",
        "indefinite retention check",
        "uncontrolled pii retention policy",
        "automated deletion lifecycle",
    ],
    agent_class=PiDataRetentionPolicyEnforcer,
    input_factory=lambda goal, ctx: RetentionInput(
        policy_content=ctx.get("policy_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiRuntimeAnomalySentry",
    keywords=[
        "runtime anomaly sentry",
        "oom container logs audit",
        "unauthorized shell execution runtime",
        "uncontrolled high fault rates sentry",
    ],
    agent_class=PiRuntimeAnomalySentry,
    input_factory=lambda goal, ctx: RuntimeInput(
        metrics_content=ctx.get("metrics_content", ctx.get("content", goal)),
    ),
)
AgentRouter.register(
    agent_name="PiHipaaComplianceAuditor",
    keywords=[
        "hipaa compliance audit",
        "phi exposure check",
        "phi identifier scan",
        "hipaa phi audit",
        "ephi violation",
        "baa reference audit",
        "healthcare privacy scan",
    ],
    agent_class=PiHipaaComplianceAuditor,
    input_factory=lambda goal, ctx: HipaaAuditInput(
        code_content=ctx.get("code_content", ctx.get("content", goal)),
        file_path=ctx.get("file_path", ""),
        component_type=ctx.get("component_type", "unknown"),
    ),
)
AgentRouter.register(
    agent_name="PiPciDssAuditor",
    keywords=[
        "pci dss audit",
        "cardholder data scan",
        "chd violation check",
        "pan exposure audit",
        "cvv storage check",
        "payment card compliance",
        "pci compliance scan",
    ],
    agent_class=PiPciDssAuditor,
    input_factory=lambda goal, ctx: PciDssInput(
        code_content=ctx.get("code_content", ctx.get("content", goal)),
        file_path=ctx.get("file_path", ""),
        component_type=ctx.get("component_type", "unknown"),
    ),
)
AgentRouter.register(
    agent_name="PiMobileSecurityAuditor",
    keywords=[
        "mobile security audit",
        "masvs audit",
        "mastg check",
        "android security scan",
        "ios security audit",
        "flutter security check",
        "react native security",
        "mobile keystore audit",
        "certificate pinning check",
    ],
    agent_class=PiMobileSecurityAuditor,
    input_factory=lambda goal, ctx: MobileAuditInput(
        code_content=ctx.get("code_content", ctx.get("content", goal)),
        file_path=ctx.get("file_path", ""),
        platform=ctx.get("platform", "unknown"),
    ),
)
AgentRouter.register(
    agent_name="PiBotDetectionEvasionSentry",
    keywords=[
        "bot detection evasion sentry",
        "waf bypass pattern scan",
        "canvas fingerprint synthesis",
        "gpu string pool detection",
        "tls fingerprint spoofing",
        "proof of work solver detection",
        "cloudflare jsd bypass pattern",
        "datadome vm pattern",
    ],
    agent_class=PiBotDetectionEvasionSentry,
    input_factory=lambda goal, ctx: BotEvasionInput(
        code_content=ctx.get("code_content", ctx.get("content", goal)),
        file_path=ctx.get("file_path", ""),
        context=ctx.get("context", "unknown"),
    ),
)
AgentRouter.register(
    agent_name="PiSshCertificateSecurityAuditor",
    keywords=[
        "ssh certificate security audit",
        "ssh cert expiry validation",
        "ssh cert principal check",
        "sshcerts security gap",
        "ssh-rsa sha1 deprecated",
        "webhook secret plaintext",
        "module signing cert audit",
    ],
    agent_class=PiSshCertificateSecurityAuditor,
    input_factory=lambda goal, ctx: SshCertInput(
        code_content=ctx.get("code_content", ctx.get("content", goal)),
        file_path=ctx.get("file_path", ""),
        has_cert_parsing=bool(ctx.get("has_cert_parsing", False)),
    ),
)
