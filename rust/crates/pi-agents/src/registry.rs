//! Name -> agent dispatch table (auto-generated from ported agents).
//!
//! Each agent exposes `run_json(&str) -> Result<String, String>`, keyed by its
//! original Python class name.

use once_cell::sync::Lazy;
use std::collections::BTreeMap;

/// JSON-in, JSON-out agent entry point.
pub type AgentFn = fn(&str) -> Result<String, String>;

pub static REGISTRY: Lazy<BTreeMap<&'static str, AgentFn>> = Lazy::new(|| {
    let mut m: BTreeMap<&'static str, AgentFn> = BTreeMap::new();
    m.insert("PiAccessControlShadow", crate::agents::access_control_shadow::run_json as AgentFn);
    m.insert("PiAdversarialEvaluatorSim", crate::agents::adversarial_evaluator_sim::run_json as AgentFn);
    m.insert("PiAgentToolExecutionGuard", crate::agents::agent_tool_execution_guard::run_json as AgentFn);
    m.insert("PiApiAuthHardcodedTokenSentry", crate::agents::api_auth_hardcoded_token_sentry::run_json as AgentFn);
    m.insert("PiAPIOWASPScanner", crate::agents::api_owasp_scanner::run_json as AgentFn);
    m.insert("PiApiReverseEngineeredAuth", crate::agents::api_reverse_engineered_auth::run_json as AgentFn);
    m.insert("PiArbitrageGuard", crate::agents::arbitrage_guard::run_json as AgentFn);
    m.insert("PiArchitectureImportBoundarySentry", crate::agents::architecture_import_boundary_sentry::run_json as AgentFn);
    m.insert("PiAssemblyLethalWeapons", crate::agents::assembly_lethal_weapons::run_json as AgentFn);
    m.insert("PiAuditLogTamperDetector", crate::agents::audit_log_tamper_detector::run_json as AgentFn);
    m.insert("PiAutomatedAnonymizer", crate::agents::automated_anonymizer::run_json as AgentFn);
    m.insert("PiAutomatedRotationEngine", crate::agents::automated_rotation_engine::run_json as AgentFn);
    m.insert("PiBackupIntegrityChecker", crate::agents::backup_integrity_checker::run_json as AgentFn);
    m.insert("PiBlockTimestampSentry", crate::agents::block_timestamp_sentry::run_json as AgentFn);
    m.insert("PiBytecodeDecompiler", crate::agents::bytecode_decompiler::run_json as AgentFn);
    m.insert("PiCavemanTokenCompressor", crate::agents::caveman_token_compressor::run_json as AgentFn);
    m.insert("PiCentralizationSentry", crate::agents::centralization_sentry::run_json as AgentFn);
    m.insert("PiCertificateRotationWatcher", crate::agents::certificate_rotation_watcher::run_json as AgentFn);
    m.insert("PiChangelogAuditor", crate::agents::changelog_auditor::run_json as AgentFn);
    m.insert("PiCloudConfigAuditor", crate::agents::cloud_config_auditor::run_json as AgentFn);
    m.insert("PiCloudRunConfigAuditor", crate::agents::cloud_run_config_auditor::run_json as AgentFn);
    m.insert("PiCodeSigningEnforcer", crate::agents::code_signing_enforcer::run_json as AgentFn);
    m.insert("PiConstantTimeAuditor", crate::agents::constant_time_auditor::run_json as AgentFn);
    m.insert("PiContainerEscapeDetector", crate::agents::container_escape_detector::run_json as AgentFn);
    m.insert("PiCrossChainMessageReplaySentry", crate::agents::cross_chain_message_replay_sentry::run_json as AgentFn);
    m.insert("PiDataFlowPrivacyMapper", crate::agents::data_flow_privacy_mapper::run_json as AgentFn);
    m.insert("PiDataRetentionPolicyEnforcer", crate::agents::data_retention_policy_enforcer::run_json as AgentFn);
    m.insert("PiDatabaseMigrationUnindexedSentry", crate::agents::database_migration_unindexed_sentry::run_json as AgentFn);
    m.insert("PiDeadCodePruner", crate::agents::dead_code_pruner::run_json as AgentFn);
    m.insert("PiDeFiMathRoundingSentry", crate::agents::defi_math_rounding_sentry::run_json as AgentFn);
    m.insert("PiDeFiSlippageGuard", crate::agents::defi_slippage_guard::run_json as AgentFn);
    m.insert("PiDelegateCallGuard", crate::agents::delegate_call_guard::run_json as AgentFn);
    m.insert("PiDependencyVulnScanner", crate::agents::dependency_vuln_scanner::run_json as AgentFn);
    m.insert("PiDeploymentSafetyGuard", crate::agents::deployment_safety_guard::run_json as AgentFn);
    m.insert("PiDepreciationScanner", crate::agents::depreciation_scanner::run_json as AgentFn);
    m.insert("PiDesignAnInterfaceValidator", crate::agents::design_an_interface_validator::run_json as AgentFn);
    m.insert("PiDeterministicOutputValid", crate::agents::deterministic_output_valid::run_json as AgentFn);
    m.insert("PiDimensionalAnalysisSentry", crate::agents::dimensional_analysis_sentry::run_json as AgentFn);
    m.insert("PiDockerComposePortExposureSentry", crate::agents::docker_compose_port_exposure_sentry::run_json as AgentFn);
    m.insert("PiDockerComposeSecuritySentry", crate::agents::docker_compose_security_sentry::run_json as AgentFn);
    m.insert("PiDockerImageScanner", crate::agents::docker_image_scanner::run_json as AgentFn);
    m.insert("PiDockerSocketPrivilegeSentry", crate::agents::docker_socket_privilege_sentry::run_json as AgentFn);
    m.insert("PiEIP4337AccountAbstractionSentry", crate::agents::eip4337_account_abstraction_sentry::run_json as AgentFn);
    m.insert("PiEIP712DomainSeparatorSentry", crate::agents::eip712_domain_separator_sentry::run_json as AgentFn);
    m.insert("PiEIP712SignatureLinter", crate::agents::eip712_signature_linter::run_json as AgentFn);
    m.insert("PiEncryptionComplianceChecker", crate::agents::encryption_compliance_checker::run_json as AgentFn);
    m.insert("PiERC20PermitPhishingGuard", crate::agents::erc20_permit_phishing_guard::run_json as AgentFn);
    m.insert("PiERC7702DelegationGuard", crate::agents::erc7702_delegation_guard::run_json as AgentFn);
    m.insert("PiExternalContractGuard", crate::agents::external_contract_guard::run_json as AgentFn);
    m.insert("PiFirewallRuleAuditor", crate::agents::firewall_rule_auditor::run_json as AgentFn);
    m.insert("PiFloatingPragmaSentry", crate::agents::floating_pragma_sentry::run_json as AgentFn);
    m.insert("PiGasGuzzlerDetector", crate::agents::gas_guzzler_detector::run_json as AgentFn);
    m.insert("PiGCPIAMPolicyRiskAuditor", crate::agents::gcp_iam_policy_risk_auditor::run_json as AgentFn);
    m.insert("PiGCPProjectIDValidator", crate::agents::gcp_project_id_validator::run_json as AgentFn);
    m.insert("PiGCPVPCConnectorValidator", crate::agents::gcp_vpc_connector_validator::run_json as AgentFn);
    m.insert("PiGCPWorkloadIdentityAuditor", crate::agents::gcp_workload_identity_auditor::run_json as AgentFn);
    m.insert("PiGitSafetyGuardrail", crate::agents::git_safety_guardrail::run_json as AgentFn);
    m.insert("PiGitSecScanner", crate::agents::git_sec_scanner::run_json as AgentFn);
    m.insert("PiGitSecretEntropyLeakSentry", crate::agents::git_secret_entropy_leak_sentry::run_json as AgentFn);
    m.insert("PiGitSecretLeakSentry", crate::agents::git_secret_leak_sentry::run_json as AgentFn);
    m.insert("PiGithubActionsUnpinnedVersion", crate::agents::github_actions_unpinned_version::run_json as AgentFn);
    m.insert("PiGrillMeQuestionnaire", crate::agents::grill_me_questionnaire::run_json as AgentFn);
    m.insert("PiGrpcProtocolInterceptor", crate::agents::grpc_protocol_interceptor::run_json as AgentFn);
    m.insert("PiGrpcWireProtocolInsecureSentry", crate::agents::grpc_wire_protocol_insecure_sentry::run_json as AgentFn);
    m.insert("PiHandoffCheckpointSentry", crate::agents::handoff_checkpoint_sentry::run_json as AgentFn);
    m.insert("PiHardcodedSecretDetector", crate::agents::hardcoded_secret_detector::run_json as AgentFn);
    m.insert("PiHotPathAllocationAuditor", crate::agents::hot_path_allocation_auditor::run_json as AgentFn);
    m.insert("PiIaCScanner", crate::agents::iac_scanner::run_json as AgentFn);
    m.insert("PiApiAuthJWTNoneAlgorithmSentry", crate::agents::jwt_none_sentry::run_json as AgentFn);
    m.insert("PiKubernetesRootExecutionLinter", crate::agents::kubernetes_root_execution_linter::run_json as AgentFn);
    m.insert("PiKubernetesSecurityAuditor", crate::agents::kubernetes_security_auditor::run_json as AgentFn);
    m.insert("PiLLMBase64EncodingDeobfuscator", crate::agents::llm_base64_encoding_deobfuscator::run_json as AgentFn);
    m.insert("PiLLMChainOfThoughtBypassSentry", crate::agents::llm_chain_of_thought_bypass_sentry::run_json as AgentFn);
    m.insert("PiLLMContextWindowDriftSentry", crate::agents::llm_context_window_drift_sentry::run_json as AgentFn);
    m.insert("PiLLMHallucinationDetector", crate::agents::llm_hallucination_detector::run_json as AgentFn);
    m.insert("PiLLMNegativeConstraintEvasion", crate::agents::llm_negative_constraint_evasion::run_json as AgentFn);
    m.insert("PiLLMOutputSanitizer", crate::agents::llm_output_sanitizer::run_json as AgentFn);
    m.insert("PiLLMPairwiseAdversarialValidator", crate::agents::llm_pairwise_adversarial_validator::run_json as AgentFn);
    m.insert("PiLLMPromptEgressLeakDetector", crate::agents::llm_prompt_egress_leak_detector::run_json as AgentFn);
    m.insert("PiLLMPromptInjectionNegativeConstraintSentry", crate::agents::llm_prompt_injection_negative_constraint_sentry::run_json as AgentFn);
    m.insert("PiLLMPromptInjectionSentry", crate::agents::llm_prompt_injection_sentry::run_json as AgentFn);
    m.insert("PiLLMPromptInjectionSystemPromptOverrideSentry", crate::agents::llm_prompt_injection_system_prompt_override_sentry::run_json as AgentFn);
    m.insert("PiLLMRecursiveRefinementJailbreak", crate::agents::llm_recursive_refinement_jailbreak::run_json as AgentFn);
    m.insert("PiLLMSystemPromptDriftSentry", crate::agents::llm_system_prompt_drift_sentry::run_json as AgentFn);
    m.insert("PiLLMSystemPromptHijackSentry", crate::agents::llm_system_prompt_hijack_sentry::run_json as AgentFn);
    m.insert("PiLogicGatekeeper", crate::agents::logic_gatekeeper::run_json as AgentFn);
    m.insert("PiMemoryZeroizeSentry", crate::agents::memory_zeroize_sentry::run_json as AgentFn);
    m.insert("PiMemorystoreConnectionAuditor", crate::agents::memorystore_connection_auditor::run_json as AgentFn);
    m.insert("PiMempoolSentry", crate::agents::mempool_sentry::run_json as AgentFn);
    m.insert("PiMisconfigPatternMatcher", crate::agents::misconfig_pattern_matcher::run_json as AgentFn);
    m.insert("PiMockDataTaintingSentry", crate::agents::mock_data_tainting_sentry::run_json as AgentFn);
    m.insert("PiNginxReverseProxyHeaderSentry", crate::agents::nginx_reverse_proxy_header_sentry::run_json as AgentFn);
    m.insert("PiNicheScraper", crate::agents::niche_scraper::run_json as AgentFn);
    m.insert("PiOracleDivergenceAudit", crate::agents::oracle_divergence_audit::run_json as AgentFn);
    m.insert("PiOracleSentry", crate::agents::oracle_sentry::run_json as AgentFn);
    m.insert("PiPatchSynthesizer", crate::agents::patch_synthesizer::run_json as AgentFn);
    m.insert("PiPhishingShield", crate::agents::phishing_shield::run_json as AgentFn);
    m.insert("PiPipelineIntegrityAuditor", crate::agents::pipeline_integrity_auditor::run_json as AgentFn);
    m.insert("PiPromptLeakBuster", crate::agents::prompt_leak_buster::run_json as AgentFn);
    m.insert("PiPubSubTopicNamingAuditor", crate::agents::pubsub_topic_naming_auditor::run_json as AgentFn);
    m.insert("PiRBACPermissionMapper", crate::agents::rbac_permission_mapper::run_json as AgentFn);
    m.insert("PiReadOnlyOracleManipulationSentry", crate::agents::read_only_oracle_manipulation_sentry::run_json as AgentFn);
    m.insert("PiReadOnlyReentrancySentry", crate::agents::read_only_reentrancy_sentry::run_json as AgentFn);
    m.insert("PiReadmeValidator", crate::agents::readme_validator::run_json as AgentFn);
    m.insert("PiReentrancyGuardSpec", crate::agents::reentrancy_guard_spec::run_json as AgentFn);
    m.insert("PiRequestRefactorPlanVerifier", crate::agents::request_refactor_plan_verifier::run_json as AgentFn);
    m.insert("PiRuntimeAnomalySentry", crate::agents::runtime_anomaly_sentry::run_json as AgentFn);
    m.insert("PiRustAnchorSecuritySentry", crate::agents::rust_anchor_security_sentry::run_json as AgentFn);
    m.insert("PiRustSolanaAccountDataValidation", crate::agents::rust_solana_account_data_validation::run_json as AgentFn);
    m.insert("PiRustSolanaArithmeticOverflowCheck", crate::agents::rust_solana_arithmetic_overflow_check::run_json as AgentFn);
    m.insert("PiRustSolanaBorshSerializationLeak", crate::agents::rust_solana_borsh_serialization_leak::run_json as AgentFn);
    m.insert("PiRustSolanaCPIInstructionSentry", crate::agents::rust_solana_cpi_instruction_sentry::run_json as AgentFn);
    m.insert("PiRustSolanaMissingSignerAssert", crate::agents::rust_solana_missing_signer_assert::run_json as AgentFn);
    m.insert("PiRustSolanaOwnerVerificationGuard", crate::agents::rust_solana_owner_verification_guard::run_json as AgentFn);
    m.insert("PiRustSolanaReentrancyCrossProgramSentry", crate::agents::rust_solana_reentrancy_cross_program_sentry::run_json as AgentFn);
    m.insert("PiRustSolanaReentrancySentry", crate::agents::rust_solana_reentrancy_sentry::run_json as AgentFn);
    m.insert("PiRustSolanaSignerAssertionSentry", crate::agents::rust_solana_signer_assertion_sentry::run_json as AgentFn);
    m.insert("PiRustSolanaSysvarClockVerification", crate::agents::rust_solana_sysvar_clock_verification::run_json as AgentFn);
    m.insert("PiRustTokioDeadlockSentry", crate::agents::rust_tokio_deadlock_sentry::run_json as AgentFn);
    m.insert("PiRustTuiResourceLimit", crate::agents::rust_tui_resource_limit::run_json as AgentFn);
    m.insert("PiSandwichMEVShield", crate::agents::sandwich_mev_shield::run_json as AgentFn);
    m.insert("PiSBOMValidator", crate::agents::sbom_validator::run_json as AgentFn);
    m.insert("PiSecretsManagerCompletenessChecker", crate::agents::secrets_manager_completeness_checker::run_json as AgentFn);
    m.insert("PiSelfDestructHunter", crate::agents::self_destruct_hunter::run_json as AgentFn);
    m.insert("PiSelfHealingPatchAgent", crate::agents::self_healing_patch_agent::run_json as AgentFn);
    m.insert("PiSemanticCommitMessageLinter", crate::agents::semantic_commit_message_linter::run_json as AgentFn);
    m.insert("PiSemanticSchemaDynamicFieldCheck", crate::agents::semantic_schema_dynamic_field_check::run_json as AgentFn);
    m.insert("PiSemanticSchemaRegistry", crate::agents::semantic_schema_registry::run_json as AgentFn);
    m.insert("PiSensitiveDataScanner", crate::agents::sensitive_data_scanner::run_json as AgentFn);
    m.insert("PiSensitiveLogLeakSentry", crate::agents::sensitive_log_leak_sentry::run_json as AgentFn);
    m.insert("PiShadowedVariableDetector", crate::agents::shadowed_variable_detector::run_json as AgentFn);
    m.insert("PiSignatureReplayScout", crate::agents::signature_replay_scout::run_json as AgentFn);
    m.insert("PiSolidityArbitraryTransferSentry", crate::agents::solidity_arbitrary_transfer_sentry::run_json as AgentFn);
    m.insert("PiSolidityArrayLengthMutationSentry", crate::agents::solidity_array_length_mutation_sentry::run_json as AgentFn);
    m.insert("PiSolidityArrayLengthSentry", crate::agents::solidity_array_length_sentry::run_json as AgentFn);
    m.insert("PiSolidityAssemblyMemorySafeSentry", crate::agents::solidity_assembly_memory_safe_sentry::run_json as AgentFn);
    m.insert("PiSolidityBlockTimestampIntervalSentry", crate::agents::solidity_block_timestamp_interval_sentry::run_json as AgentFn);
    m.insert("PiSolidityCompilerBugsSentry", crate::agents::solidity_compiler_bugs_sentry::run_json as AgentFn);
    m.insert("PiSolidityConstantPragmaValidation", crate::agents::solidity_constant_pragma_validation::run_json as AgentFn);
    m.insert("PiSolidityCreate2SaltCollisionSentry", crate::agents::solidity_create2_salt_collision_sentry::run_json as AgentFn);
    m.insert("PiSolidityDelegateCallToSelfSentry", crate::agents::solidity_delegate_call_to_self_sentry::run_json as AgentFn);
    m.insert("PiSolidityDelegatecallStorageSentry", crate::agents::solidity_delegatecall_storage_sentry::run_json as AgentFn);
    m.insert("PiSolidityDirtyMemorySentry", crate::agents::solidity_dirty_memory_sentry::run_json as AgentFn);
    m.insert("PiSolidityDivideBeforeMultiplyAuditor", crate::agents::solidity_divide_before_multiply_auditor::run_json as AgentFn);
    m.insert("PiSolidityEIP712TypehashMismatchSentry", crate::agents::solidity_eip712_typehash_mismatch_sentry::run_json as AgentFn);
    m.insert("PiSolidityERC20SafeApproveAuditor", crate::agents::solidity_erc20_safe_approve_auditor::run_json as AgentFn);
    m.insert("PiSolidityERC20TransferRecipientSentry", crate::agents::solidity_erc20_transfer_recipient_sentry::run_json as AgentFn);
    m.insert("PiSolidityERC7702CodeSentry", crate::agents::solidity_erc7702_code_sentry::run_json as AgentFn);
    m.insert("PiSolidityExternalContractsReturnCheck", crate::agents::solidity_external_contracts_return_check::run_json as AgentFn);
    m.insert("PiSolidityFlashLoanAttack", crate::agents::solidity_flash_loan_attack::run_json as AgentFn);
    m.insert("PiSolidityInitializableGapSentry", crate::agents::solidity_initializable_gap_sentry::run_json as AgentFn);
    m.insert("PiSolidityL2GasFeeSentry", crate::agents::solidity_l2_gas_fee_sentry::run_json as AgentFn);
    m.insert("PiSolidityOracleLivenessSentry", crate::agents::solidity_oracle_liveness_sentry::run_json as AgentFn);
    m.insert("PiSolidityOwnerTimelockSentry", crate::agents::solidity_owner_timelock_sentry::run_json as AgentFn);
    m.insert("PiSolidityPriceFeedFallbackSentry", crate::agents::solidity_price_feed_fallback_sentry::run_json as AgentFn);
    m.insert("PiSolidityPriceFeedSequencerSentry", crate::agents::solidity_price_feed_sequencer_sentry::run_json as AgentFn);
    m.insert("PiSolidityProxyCallTargetCheck", crate::agents::solidity_proxy_call_target_check::run_json as AgentFn);
    m.insert("PiSolidityReentrancyGuardOverlapSentry", crate::agents::solidity_reentrancy_guard_overlap_sentry::run_json as AgentFn);
    m.insert("PiSolidityReentrancyMutexSentry", crate::agents::solidity_reentrancy_mutex_sentry::run_json as AgentFn);
    m.insert("PiSoliditySelfdestructCodeEraseSentry", crate::agents::solidity_selfdestruct_code_erase_sentry::run_json as AgentFn);
    m.insert("PiSoliditySignatureMalleabilitySentry", crate::agents::solidity_signature_malleability_sentry::run_json as AgentFn);
    m.insert("PiSoliditySignatureOmittedReplaySentry", crate::agents::solidity_signature_omitted_replay_sentry::run_json as AgentFn);
    m.insert("PiSolidityTransientStorageReentrancySentry", crate::agents::solidity_transient_storage_reentrancy_sentry::run_json as AgentFn);
    m.insert("PiSolidityTransientStorageSentry", crate::agents::solidity_transient_storage_sentry::run_json as AgentFn);
    m.insert("PiSolidityTxOriginCallCheckSentry", crate::agents::solidity_tx_origin_call_check_sentry::run_json as AgentFn);
    m.insert("PiSolidityUnboundedLoopsInStateMutation", crate::agents::solidity_unbounded_loops_in_state_mutation::run_json as AgentFn);
    m.insert("PiSolidityUndeclaredReturnVariableSentry", crate::agents::solidity_undeclared_return_variable_sentry::run_json as AgentFn);
    m.insert("PiSolidityUpgradeableInitializerSentry", crate::agents::solidity_upgradeable_initializer_sentry::run_json as AgentFn);
    m.insert("PiSolidityYulMemoryOffsetAudit", crate::agents::solidity_yul_memory_offset_audit::run_json as AgentFn);
    m.insert("PiStructuredLoggingEnforcer", crate::agents::structured_logging_enforcer::run_json as AgentFn);
    m.insert("PiSupplyChainIntegrityChecker", crate::agents::supply_chain_integrity_checker::run_json as AgentFn);
    m.insert("PiTddAssertionCoverage", crate::agents::tdd_assertion_coverage::run_json as AgentFn);
    m.insert("PiTddMockingSanityChecker", crate::agents::tdd_mocking_sanity_checker::run_json as AgentFn);
    m.insert("PiTddTestFileVerifier", crate::agents::tdd_test_file_verifier::run_json as AgentFn);
    m.insert("PiTerraformStateCredentialSentry", crate::agents::terraform_state_credential_sentry::run_json as AgentFn);
    m.insert("PiThreatModelGenerator", crate::agents::threat_model_generator::run_json as AgentFn);
    m.insert("PiToIssuesBreakdown", crate::agents::to_issues_breakdown::run_json as AgentFn);
    m.insert("PiToPrdValidator", crate::agents::to_prd_validator::run_json as AgentFn);
    m.insert("PiTokenTaxDetector", crate::agents::token_tax_detector::run_json as AgentFn);
    m.insert("PiTriageBugLabels", crate::agents::triage_bug_labels::run_json as AgentFn);
    m.insert("PiTxOriginSentry", crate::agents::tx_origin_sentry::run_json as AgentFn);
    m.insert("PiTypeScriptWizardryCheck", crate::agents::typescript_wizardry_check::run_json as AgentFn);
    m.insert("PiUninitializedStateSentry", crate::agents::uninitialized_state_sentry::run_json as AgentFn);
    m.insert("PiUniswapV3PoolSentry", crate::agents::uniswap_v3_pool_sentry::run_json as AgentFn);
    m.insert("PiVertexAIModelIDValidator", crate::agents::vertex_ai_model_id_validator::run_json as AgentFn);
    m.insert("PiVyperExternalCallSentry", crate::agents::vyper_external_call_sentry::run_json as AgentFn);
    m.insert("PiVyperSecScanner", crate::agents::vyper_sec_scanner::run_json as AgentFn);
    m.insert("PiVyperStateLockSentry", crate::agents::vyper_state_lock_sentry::run_json as AgentFn);
    m.insert("PiVyperStorageLayoutCollisionSentry", crate::agents::vyper_storage_layout_collision_sentry::run_json as AgentFn);
    m.insert("PiWebVulnScanner", crate::agents::web_vuln_scanner::run_json as AgentFn);
    m.insert("PiZeroKnowledgeCircuitSentry", crate::agents::zero_knowledge_circuit_sentry::run_json as AgentFn);
    m.insert("PiZeroTrustExecutionDomain", crate::agents::zero_trust_execution_domain::run_json as AgentFn);
    m.insert("PiZeroTrustVerifier", crate::agents::zero_trust_verifier::run_json as AgentFn);
    m.insert("PiZKCircomDivisionSentry", crate::agents::zk_circom_division_sentry::run_json as AgentFn);
    m.insert("PiZKCircomShadowSignalSentry", crate::agents::zk_circom_shadow_signal_sentry::run_json as AgentFn);
    m.insert("PiZKCircomUnderconstrainedSentry", crate::agents::zk_circom_underconstrained_sentry::run_json as AgentFn);
    m.insert("PiZKDivByZeroConstraintAuditor", crate::agents::zk_div_by_zero_constraint_auditor::run_json as AgentFn);
    m.insert("PiZKNonPrimeFieldRangeSentry", crate::agents::zk_non_prime_field_range_sentry::run_json as AgentFn);
    m.insert("PiZKProofForgingValidationSentry", crate::agents::zk_proof_forging_validation_sentry::run_json as AgentFn);
    m.insert("PiZKProofPublicInputVerif", crate::agents::zk_proof_public_input_verif::run_json as AgentFn);
    m.insert("PiZKPublicInputLeakageAuditor", crate::agents::zk_public_input_leakage_auditor::run_json as AgentFn);
    m.insert("PiZKSignalShadowingSignalSentry", crate::agents::zk_signal_shadowing_signal_sentry::run_json as AgentFn);
    m.insert("PiZKSignalUnconstrainedConstraint", crate::agents::zk_signal_unconstrained_constraint::run_json as AgentFn);
    m.insert("PiZKUnusedConstraintVariables", crate::agents::zk_unused_constraint_variables::run_json as AgentFn);
    m.insert("PiZoomOutSystemExplainer", crate::agents::zoom_out_system_explainer::run_json as AgentFn);
    m
});

/// Run a registered agent by name.
pub fn run_agent(name: &str, input_json: &str) -> Result<String, String> {
    match REGISTRY.get(name) {
        Some(f) => f(input_json),
        None => Err(format!("unknown agent: {name}")),
    }
}

/// Sorted list of every registered agent name.
pub fn list_agents() -> Vec<String> {
    REGISTRY.keys().map(|s| s.to_string()).collect()
}
