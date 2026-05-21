# src/pi_micro_agents/orchestrator/chain_engine.py
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Tuple, Type

from pydantic import BaseModel

from pi_agent_chain.ledger import StateLedger
from pi_agent_chain.models import ExecutionTrace
from pi_micro_agents.orchestrator.consensus import run_with_consensus
from pi_micro_agents.orchestrator.router import AgentRoute, AgentRouter
from pi_micro_agents.orchestrator.shield import PiOrchestratorShield
from pi_micro_agents.pi_spend_hunter import PiSpendAnomalyHunter


class AgentChainCompiler:
    """Parses goals or context definitions into an executable sequence of AgentRoutes."""

    @classmethod
    def compile_chain(cls, goal: str, context: Dict[str, Any]) -> List[AgentRoute]:
        # 0. Check predefined collaboration templates
        g_lower = goal.lower()
        collaboration_templates = {
            "cross-chain yield": ["PiOracleDivergenceAudit", "PiGasGuzzlerDetector", "PiPublisherDispatch"],
            "gas optimization": ["PiOracleDivergenceAudit", "PiGasGuzzlerDetector", "PiPublisherDispatch"],
            "contract resilience": ["PiReentrancySentry", "PiAssemblyLethalWeapons", "PiArithmeticAuditor"],
            "fuzzing": ["PiReentrancySentry", "PiAssemblyLethalWeapons", "PiArithmeticAuditor"],
            "privilege drift": ["PiAccessControlShadow", "PiApiAuthHardcodedTokenSentry", "PiZeroTrustExecutionDomain"],
            "gateway audit": ["PiAccessControlShadow", "PiApiAuthHardcodedTokenSentry", "PiZeroTrustExecutionDomain"],
            "vault compliance": ["PiERC4626VaultGuard", "PiStorageLayoutDrift", "PiToPrdValidator"],
            "erc4626": ["PiERC4626VaultGuard", "PiStorageLayoutDrift", "PiToPrdValidator"],
            "container ingress": ["PiNginxReverseProxyHeaderSentry", "PiDockerComposeSecuritySentry", "PiDockerSocketPrivilegeSentry"],
            "proxy defender": ["PiNginxReverseProxyHeaderSentry", "PiDockerComposeSecuritySentry", "PiDockerSocketPrivilegeSentry"],
            "hallucination": ["PiLLMHallucinationDetector", "PiPromptLeakBuster", "PiLLMPromptEgressLeakDetector"],
            "leak buster": ["PiLLMHallucinationDetector", "PiPromptLeakBuster", "PiLLMPromptEgressLeakDetector"],
            "ci/cd release": ["PiGithubActionsUnpinnedVersion", "PiGitSafetyGuardrail", "PiChangelogAuditor"],
            "dependency alignment": ["PiGithubActionsUnpinnedVersion", "PiGitSafetyGuardrail", "PiChangelogAuditor"],
            "zk-circuit soundness": ["PiZKNonPrimeFieldRangeSentry", "PiZKSignalUnconstrainedConstraint", "PiZKUnusedConstraintVariables"],
            "zk auditing": ["PiZKNonPrimeFieldRangeSentry", "PiZKSignalUnconstrainedConstraint", "PiZKUnusedConstraintVariables"],
            "solana cpi": ["PiRustSolanaAccountDataValidation", "PiRustSolanaCPIInstructionSentry", "PiRustSolanaOwnerVerificationGuard"],
            "solana cpi security": ["PiRustSolanaAccountDataValidation", "PiRustSolanaCPIInstructionSentry", "PiRustSolanaOwnerVerificationGuard"],
            "database migration": ["PiMockDataTaintingSentry", "PiDatabaseMigrationUnindexedSentry", "PiTddMockingSanityChecker"],
            "qa validation": ["PiMockDataTaintingSentry", "PiDatabaseMigrationUnindexedSentry", "PiTddMockingSanityChecker"],
            # 20 New Playbooks Integration
            "web application vulnerability scanning": ["PiWebVulnScanner", "PiSelfHealingPatchAgent", "PiDeploymentSafetyGuard"],
            "cloud cost optimization": ["PiCloudCostAnalyzer", "PiIdleResourceSentry", "PiBudgetAnomalyGuard"],
            "api security & rate limiting": ["PiAPIRateLimitSentry", "PiApiAuthHardcodedTokenSentry", "PiEndpointAbuseGuard"],
            "database query optimization": ["PiSlowQueryDetector", "PiSQLInjectionSentry", "PiIndexRecommendationEngine"],
            "container image security": ["PiDockerImageScanner", "PiDockerComposeSecuritySentry", "PiContainerEscapeDetector"],
            "ci/cd pipeline integrity": ["PiGithubActionsUnpinnedVersion", "PiGitSecretLeakSentry", "PiPipelineIntegrityAuditor"],
            "frontend supply chain": ["PiNPMDependencyVulnScanner", "PiGitSecScanner", "PiTreeShakingOptimizer"],
            "llm output sanitization": ["PiLLMOutputSanitizer", "PiLLMHallucinationDetector", "PiLLMPromptEgressLeakDetector"],
            "data privacy compliance": ["PiDataFlowPrivacyMapper", "PiSensitiveDataScanner", "PiAutomatedAnonymizer"],
            "logging & observability anomaly": ["PiSensitiveLogLeakSentry", "PiGitSecretEntropyLeakSentry", "PiStructuredLoggingEnforcer"],
            "access control & privilege escalation": ["PiIAMOverPermissionSentry", "PiAccessControlShadow", "PiLeastPrivilegeRemediator"],
            "documentation & code comment consistency": ["PiDocsOutdatedChecker", "PiReadmeValidator", "PiAutoDocsGenerator"],
            "performance profiling": ["PiMemoryLeakDetector", "PiHotPathAllocationAuditor", "PiBottleneckOptimizer"],
            "mobile app security": ["PiMobilePermissionSentry", "PiAppDataLeakDetector", "PiRuntimeHardeningGuard"],
            "network traffic analysis": ["PiNetworkTrafficSentry", "PiDDoSPatternDetector", "PiTrafficOptimizer"],
            "backup & disaster recovery": ["PiBackupIntegritySentry", "PiRecoveryTimeAuditor", "PiAutomatedRestoreTester"],
            "accessibility & wcag compliance": ["PiAccessibilityScanner", "PiContrastRatioAuditor", "PiAutoRemediationEngine"],
            "secrets management & rotation": ["PiHardcodedSecretDetector", "PiGitSecretLeakSentry", "PiAutomatedRotationEngine"],
            "iac security & drift": ["PiTerraformDriftDetector", "PiTerraformStateCredentialSentry", "PiInfrastructureComplianceAuditor"],
            "frontend performance & core web vitals": ["PiLighthouseAuditor", "PiBundleSizeSentry", "PiCoreWebVitalsOptimizer"]
        }

        for keyword, chain_names in collaboration_templates.items():
            if keyword in g_lower:
                routes = []
                for name in chain_names:
                    route = cls._resolve_single_agent(name)
                    if route:
                        routes.append(route)
                if len(routes) == len(chain_names):
                    return routes

        # 1. Check if an explicit chain is passed via context
        chain_list = context.get("chain") or context.get("agent_chain")
        if chain_list and isinstance(chain_list, list):
            routes = []
            for name in chain_list:
                route = cls._resolve_single_agent(name)
                if route:
                    routes.append(route)
            if routes:
                return routes

        # 2. Parse from goal text (e.g. "PiGitSecScanner then PiSelfHealingPatchAgent" or "A -> B")
        segments = []
        if "->" in goal:
            segments = [s.strip() for s in goal.split("->") if s.strip()]
        elif " then " in goal.lower():
            segments = [s.strip() for s in re.split(r"\bthen\b", goal, flags=re.IGNORECASE) if s.strip()]
        elif "," in goal:
            # Check if comma-separated list of agent names
            candidates = [s.strip() for s in goal.split(",") if s.strip()]
            valid_candidates = []
            for c in candidates:
                if cls._resolve_single_agent(c):
                    valid_candidates.append(c)
            if len(valid_candidates) >= 2:
                segments = valid_candidates

        if segments:
            routes = []
            for seg in segments:
                # Clean prefix words like "Run", "Please start", etc.
                cleaned = re.sub(r"^(run|execute|please start|activate|start)\s+", "", seg, flags=re.IGNORECASE).strip()
                route = cls._resolve_single_agent(cleaned)
                if route:
                    routes.append(route)
            if routes:
                return routes

        # 3. Fallback: Autonomous Goal Decomposition & Task Decomposer
        g_lower = goal.lower()
        sub_tasks = []
        # Split on coordinating conjunctions, separators, or chaining arrows
        parts = re.split(r"\band\b|\bthen\b|->|;", g_lower)
        for part in parts:
            part = part.strip()
            if len(part) >= 3:
                sub_tasks.append(part)

        if len(sub_tasks) < 2:
            return []

        # Define semantic domain keyword aliases for the top chainable agents
        domain_mapping = {
            "PiPromptShield": {"prompt shield", "injection", "jailbreak", "shield", "guardrail"},
            "PiGitSecScanner": {"requirements", "package.json", "dependency", "dependencies", "unpinned"},
            "PiSelfHealingPatchAgent": {"heal", "healer", "patch", "repair", "remediate", "remediation", "self-heal", "fix"},
            "PiArithmeticAuditor": {"arithmetic", "math", "overflow", "underflow", "rounding", "precision"},
            "PiReentrancySentry": {"reentrancy", "checks-effects", "mutex", "reentrant"},
            "PiDeFiSlippageGuard": {"slippage", "swap", "mev", "sandwich", "frontrun"},
            "PiOracleDivergenceAudit": {"oracle", "divergence", "price feed", "stale"},
            "PiStorageLayoutDrift": {"storage layout", "drift", "gap", "upgradeable", "initializer", "collision"},
            "PiTokenTaxDetector": {"token tax", "fee-on-transfer", "honeypot", "tax"},
            "PiCentralizationSentry": {"centralization", "multisig", "timelock", "admin", "privilege"},
            "PiPublisherDispatch": {"publish", "deploy", "dispatch", "commit"}
        }

        # Precedence order mapping for clean sequencing (lower value = runs earlier)
        precedence_order = {
            "PiPromptShield": 1,
            "PiGitSecScanner": 2,
            "PiSelfHealingPatchAgent": 3,
            "PiArithmeticAuditor": 4,
            "PiReentrancySentry": 4,
            "PiDeFiSlippageGuard": 4,
            "PiOracleDivergenceAudit": 4,
            "PiStorageLayoutDrift": 4,
            "PiTokenTaxDetector": 4,
            "PiCentralizationSentry": 4,
            "PiPublisherDispatch": 5
        }

        task_indicators = {"scan", "scanner", "check", "checker", "audit", "auditor", "heal", "healer", "patch", "repair", "remediate", "fix", "verify", "verifier", "sentry", "guard", "deploy", "publish", "run", "test", "linter", "scout", "hunter", "shield", "protect"}
        matched_agent_names = []

        for idx, sub_task in enumerate(sub_tasks):
            # Check if this sub-task is valid (is first, or contains at least one task indicator verb)
            sub_tokens = set(re.findall(r'[a-zA-Z0-9]+', sub_task))
            if idx > 0 and not sub_tokens.intersection(task_indicators):
                continue

            sub_matched = []
            # Match against domain mapping
            for agent_name, keywords in domain_mapping.items():
                for kw in keywords:
                    pattern = rf"\b{re.escape(kw)}\b"
                    if re.search(pattern, sub_task) or kw in sub_task:
                        sub_matched.append(agent_name)
                        break

            # Supplement with AgentRouter's default keywords to support other agents
            for route in AgentRouter.routes:
                if route.agent_name in domain_mapping:
                    continue
                if route.agent_name == "NicheCurationPipelineChain":
                    continue
                for kw in route.keywords:
                    pattern = rf"\b{re.escape(kw.lower())}\b"
                    if re.search(pattern, sub_task) or kw.lower() in sub_task:
                        sub_matched.append(route.agent_name)
                        break

            for name in sub_matched:
                if name not in matched_agent_names:
                    matched_agent_names.append(name)

        if len(matched_agent_names) >= 2:
            # Sort by precedence hierarchy, then preserve original parsed position
            def sort_key(name):
                prec = precedence_order.get(name, 4)
                keywords = domain_mapping.get(name, set())
                first_idx = len(g_lower)
                for kw in keywords:
                    idx = g_lower.find(kw)
                    if idx != -1:
                        first_idx = min(first_idx, idx)
                return (prec, first_idx)

            matched_agent_names.sort(key=sort_key)
            
            # Deduplicate while preserving order
            final_agent_names = []
            seen = set()
            for name in matched_agent_names:
                if name not in seen:
                    final_agent_names.append(name)
                    seen.add(name)

            # Resolve actual routes
            routes = []
            for name in final_agent_names:
                route = cls._resolve_single_agent(name)
                if route:
                    routes.append(route)
            
            if len(routes) >= 2:
                return routes

        return []

    @classmethod
    def _resolve_single_agent(cls, name: str) -> AgentRoute | None:
        name_clean = name.strip().lower()
        # Direct match
        for route in AgentRouter.routes:
            if route.agent_name.lower() == name_clean:
                return route
        # Substring/Class match
        for route in AgentRouter.routes:
            if name_clean in route.agent_name.lower() or name_clean in route.agent_class.__name__.lower():
                return route
        # Keyword match fallback
        for route in AgentRouter.routes:
            if any(kw in name_clean for kw in route.keywords):
                return route
        return None


class SchemaParameterMapper:
    """Deterministic I/O normalizer to map attributes between adjacent execution steps."""

    @classmethod
    def map_output_to_input(
        cls,
        prev_output: BaseModel | Dict[str, Any] | None,
        target_route: AgentRoute,
        goal: str,
        global_context: Dict[str, Any]
    ) -> BaseModel:
        # Build normalized context
        ctx = {**global_context}

        if prev_output:
            out_dict = prev_output if isinstance(prev_output, dict) else prev_output.model_dump()
            # Overlay all output fields into the execution context
            ctx.update(out_dict)

            # Standard Synonyms Normalization
            synonyms = {
                "file_path": ["filename", "path", "file"],
                "filename": ["file_path", "path", "file"],
                "source_code": ["content", "solidity_code", "vyper_code", "text", "text_payload", "code_content"],
                "solidity_code": ["content", "source_code", "text", "text_payload"],
                "vyper_code": ["content", "source_code", "text", "text_payload"],
                "vulnerability_type": ["vulnerability_id"],
                "vulnerability_id": ["vulnerability_type"],
            }

            for target, srcs in synonyms.items():
                if target not in ctx or not ctx[target]:
                    for src in srcs:
                        if src in ctx and ctx[src]:
                            ctx[target] = ctx[src]
                            break

            # Specialized logic: Scanner Output -> SelfHealingInput extraction
            if target_route.agent_name == "PiSelfHealingPatchAgent":
                findings = out_dict.get("flagged_vulnerabilities") or out_dict.get("flagged_findings") or []
                lines = []
                vuln_type = "UNPINNED_DEP"

                for finding in findings:
                    finding_str = str(finding).lower()
                    # 1. Parse line number using regex
                    match = re.search(r"line\s*:?\s*(\d+)", finding_str)
                    if match:
                        lines.append(int(match.group(1)))

                    # 2. Heuristic check for vulnerability type
                    if "eval" in finding_str or "exec" in finding_str:
                        vuln_type = "DANGEROUS_EVAL"
                    elif "unpinned" in finding_str or "dependency" in finding_str:
                        vuln_type = "UNPINNED_DEP"

                if lines:
                    ctx["vulnerable_lines"] = sorted(list(set(lines)))
                else:
                    ctx["vulnerable_lines"] = [1]
                ctx["vulnerability_type"] = vuln_type

        # Instantiate input envelope using route's input factory
        input_envelope = target_route.input_factory(goal, ctx)

        # Secure attribute-level fallback override
        for field_name in input_envelope.model_fields.keys():
            current_val = getattr(input_envelope, field_name, None)
            if current_val is None or current_val == "" or current_val == []:
                # Try to pull directly from ctx
                if field_name in ctx:
                    setattr(input_envelope, field_name, ctx[field_name])
                # Direct check synonyms fallback
                elif field_name == "solidity_code" and "source_code" in ctx:
                    setattr(input_envelope, field_name, ctx["source_code"])
                elif field_name == "source_code" and "solidity_code" in ctx:
                    setattr(input_envelope, field_name, ctx["solidity_code"])

        return input_envelope


class ChainExecutionEngine:
    """Deterministic Multi-Agent Chain Execution Lifecycle coordinator."""

    def __init__(self, orchestrator: Any, ledger: StateLedger) -> None:
        self.orchestrator = orchestrator
        self.ledger = ledger

    def execute_chain(self, routes: List[AgentRoute], goal: str, context: Dict[str, Any]) -> Dict[str, Any]:
        prev_output = None
        latencies = []
        step_receipts = []
        is_strict = os.getenv("PI_ORCHESTRATOR_STRICT_MODE", "true").lower() == "true"
        defensive_only = os.getenv("PI_ORCHESTRATOR_DEFENSIVE_ONLY", "false").lower() == "true"
        chain_success = True

        for idx, route in enumerate(routes):
            start_step = time.perf_counter()

            # 1. Map Inputs
            input_envelope = SchemaParameterMapper.map_output_to_input(
                prev_output, route, goal, {**context, **(prev_output.model_dump() if prev_output else {})}
            )

            # 2. Strict Ingress safety checks on mapped input/context
            step_ctx = {
                **(prev_output.model_dump() if hasattr(prev_output, "model_dump") else {}),
                **context
            }

            # Check defensive-only
            if defensive_only or PiOrchestratorShield.check_defensive_only(step_ctx):
                raise ValueError("Blocked: Defensive-only execution mode rejects shell commands/code execution payloads.")

            # Command Safety
            cmd_viol = PiOrchestratorShield.check_command_safety(step_ctx)
            if cmd_viol and is_strict:
                raise ValueError(f"Blocked: Proposed shell command triggers active safety gate: {cmd_viol[1]}")

            # AST Safety
            if route.agent_name not in [
                "PiGitSecScanner", "PiSelfHealingPatchAgent", "PiReentrancySentry", "PiAccessControlVerifier",
                "PiFlashLoanDefender", "PiArithmeticAuditor", "PiDelegateCallGuard", "PiSignatureReplayScout",
                "PiBytecodeDecompiler", "PiVyperSecScanner", "PiSelfDestructHunter", "PiOracleDivergenceAudit",
                "PiTokenTaxDetector", "PiTxOriginSentry", "PiReadOnlyReentrancySentry", "PiUninitializedStateSentry",
                "PiShadowedVariableDetector", "PiBlockTimestampSentry", "PiStorageLayoutDrift", "PiERC4626VaultGuard",
                "PiCrossChainBridgeAuditor", "PiGasGuzzlerDetector", "PiAssemblyLethalWeapons", "PiLogicGatekeeper",
                "PiPhishingShield", "PiExternalContractGuard", "PiCentralizationSentry", "PiFloatingPragmaSentry",
                "PiUpgradeDefectDetector", "PiDoSGasLimitsSentry", "PiDeFiSlippageGuard",
                "PiConstantTimeAuditor", "PiMemoryZeroizeSentry", "PiDimensionalAnalysisSentry",
                "PiAgentToolExecutionGuard", "PiHotPathAllocationAuditor"
            ]:
                ast_viols = PiOrchestratorShield.check_ast_safety(step_ctx)
                if ast_viols and is_strict:
                    raise ValueError(f"Blocked: Proposed Python code contains forbidden structures: {', '.join(ast_viols)}")

            # 3. Run parallel consensus
            success, risk_score, summary, details, alerts = run_with_consensus(
                self.orchestrator, route.agent_class, input_envelope, goal, context, route.agent_name
            )

            step_latency = (time.perf_counter() - start_step) * 1000
            latencies.append(step_latency)

            # Reconstruct Pydantic/Dict Output
            # We want to keep the final verdict output as the step's prev_output
            # Locate the majority output from consensus outcomes
            consensus_telemetry = details.get("consensus_telemetry", {})
            votes = consensus_telemetry.get("votes", [])

            # Construct clean output matching agent's class output
            from pi_micro_agents.orchestrator.consensus import get_comparable_dict
            prev_output = input_envelope # default fallback
            # Find the actual Pydantic output model
            try:
                # instantiate standard output class if possible
                out_cls = self._resolve_output_class(route.agent_name)
                if out_cls:
                    prev_output = out_cls(**details)
            except Exception:
                pass

            # 4. Commit Independent Execution Trace to SQLite StateLedger
            trace_id = "trace_chain_step_" + hashlib.md5(f"{route.agent_name}_{time.time()}".encode()).hexdigest()[:8]
            payload_hash = hashlib.sha256(input_envelope.model_dump_json().encode()).hexdigest()

            trace = ExecutionTrace(
                trace_id=trace_id,
                node_name=route.agent_name,
                input_payload_hash=payload_hash,
                llm_seed=1337,
                llm_temperature=0.0,
                raw_output=json.dumps(details),
                is_valid_type=success,
                error_message=", ".join(alerts) if alerts else None
            )
            self.ledger.append(trace)

            step_receipts.append({
                "step_index": idx + 1,
                "agent_name": route.agent_name,
                "success": success,
                "risk_score": risk_score,
                "latency_ms": step_latency,
                "summary": summary,
                "details": details,
                "alerts": alerts,
                "consensus_telemetry": consensus_telemetry
            })

            # Check strict mode gating for vulnerabilities found by the agent or direct step failure
            if not success or (is_strict and risk_score >= 80.0):
                chain_success = False
                break

        return {
            "success": chain_success,
            "chain_receipts": step_receipts,
            "total_latency_ms": sum(latencies),
            "average_latency_ms": sum(latencies) / len(latencies) if latencies else 0.0,
            "final_details": prev_output.model_dump() if hasattr(prev_output, "model_dump") else dict(prev_output) if prev_output else {}
        }

    def _resolve_output_class(self, agent_name: str) -> Type[BaseModel] | None:
        from pi_micro_agents.pi_web_vuln_scanner import WebVulnOutput
        from pi_micro_agents.pi_deployment_safety_guard import DeploymentSafetyOutput
        from pi_micro_agents.pi_pipeline_integrity_auditor import PipelineIntegrityOutput
        from pi_micro_agents.orchestrator.consensus import (
            AccessControlOutput,
            ArbitrageOutput,
            ArithmeticOutput,
            AssemblySafetyOutput,
            BlockTimestampOutput,
            BytecodeDecompilerOutput,
            CentralizationOutput,
            BridgeAuditOutput,
            DeFiSlippageOutput,
            DoSGasLimitsOutput,
            VaultGuardOutput,
            ExternalContractGuardOutput,
            FlashLoanOutput,
            PragmaSentryOutput,
            GasGuzzlerOutput,
            GitSecOutput,
            LogicGatekeeperOutput,
            MempoolTxOutput,
            OracleDivergenceOutput,
            OracleSentryOutput,
            PhishingShieldOutput,
            PublisherOutput,
            ReadOnlyReentrancyOutput,
            ReentrancyOutput,
            SelfDestructHunterOutput,
            SelfHealingOutput,
            ShadowedVariableOutput,
            StorageDriftOutput,
            TokenTaxOutput,
            TxOriginOutput,
            UninitializedOutput,
            UpgradeDefectOutput,
            VyperScannerOutput,
            ConstantTimeOutput,
            MemoryZeroizeOutput,
            DimensionalAnalysisOutput,
            AgentToolGuardOutput,
            HotPathAllocationOutput,
            CavemanCompressorOutput,
            GrillMeOutput,
            HandoffOutput,
            ToPrdOutput,
            ToIssuesOutput,
            TriageOutput,
            ZoomOutOutput,
            DesignAnInterfaceOutput,
            RequestRefactorOutput,
            TddTestFileOutput,
            TddAssertionOutput,
            TddMockingOutput,
            GitSafetyOutput,
            TypeScriptWizardryOutput,
            ImportBoundaryOutput,
            DepreciationOutput,
            DeadCodeOutput,
            MockDataTaintingOutput,
            ReadmeOutput,
            ChangelogOutput,
            AstDepthOutput,
            RecursionOutput,
            MagicNumberOutput,
            ErrorCatchOutput,
            CommitLinterOutput
        )

        mapping = {
            "PiArbitrageGuard": ArbitrageOutput,
            "PiMempoolSentry": MempoolTxOutput,
            "PiGitSecScanner": GitSecOutput,
            "PiPublisherDispatch": PublisherOutput,
            "PiOracleSentry": OracleSentryOutput,
            "PiSelfHealingPatchAgent": SelfHealingOutput,
            "PiReentrancySentry": ReentrancyOutput,
            "PiAccessControlVerifier": AccessControlOutput,
            "PiFlashLoanDefender": FlashLoanOutput,
            "PiArithmeticAuditor": ArithmeticOutput,
            "PiBytecodeDecompiler": BytecodeDecompilerOutput,
            "PiVyperSecScanner": VyperScannerOutput,
            "PiSelfDestructHunter": SelfDestructHunterOutput,
            "PiOracleDivergenceAudit": OracleDivergenceOutput,
            "PiTokenTaxDetector": TokenTaxOutput,
            "PiTxOriginSentry": TxOriginOutput,
            "PiReadOnlyReentrancySentry": ReadOnlyReentrancyOutput,
            "PiUninitializedStateSentry": UninitializedOutput,
            "PiShadowedVariableDetector": ShadowedVariableOutput,
            "PiBlockTimestampSentry": BlockTimestampOutput,
            "PiStorageLayoutDrift": StorageDriftOutput,
            "PiERC4626VaultGuard": VaultGuardOutput,
            "PiCrossChainBridgeAuditor": BridgeAuditOutput,
            "PiGasGuzzlerDetector": GasGuzzlerOutput,
            "PiAssemblyLethalWeapons": AssemblySafetyOutput,
            "PiLogicGatekeeper": LogicGatekeeperOutput,
            "PiPhishingShield": PhishingShieldOutput,
            "PiExternalContractGuard": ExternalContractGuardOutput,
            "PiCentralizationSentry": CentralizationOutput,
            "PiFloatingPragmaSentry": PragmaSentryOutput,
            "PiUpgradeDefectDetector": UpgradeDefectOutput,
            "PiDoSGasLimitsSentry": DoSGasLimitsOutput,
            "PiDeFiSlippageGuard": DeFiSlippageOutput,
            "PiConstantTimeAuditor": ConstantTimeOutput,
            "PiMemoryZeroizeSentry": MemoryZeroizeOutput,
            "PiDimensionalAnalysisSentry": DimensionalAnalysisOutput,
            "PiAgentToolExecutionGuard": AgentToolGuardOutput,
            "PiHotPathAllocationAuditor": HotPathAllocationOutput,
            "PiCavemanTokenCompressor": CavemanCompressorOutput,
            "PiGrillMeQuestionnaire": GrillMeOutput,
            "PiHandoffCheckpointSentry": HandoffOutput,
            "PiToPrdValidator": ToPrdOutput,
            "PiToIssuesBreakdown": ToIssuesOutput,
            "PiTriageBugLabels": TriageOutput,
            "PiZoomOutSystemExplainer": ZoomOutOutput,
            "PiDesignAnInterfaceValidator": DesignAnInterfaceOutput,
            "PiRequestRefactorPlanVerifier": RequestRefactorOutput,
            "PiTddTestFileVerifier": TddTestFileOutput,
            "PiTddAssertionCoverage": TddAssertionOutput,
            "PiTddMockingSanityChecker": TddMockingOutput,
            "PiGitSafetyGuardrail": GitSafetyOutput,
            "PiTypeScriptWizardryCheck": TypeScriptWizardryOutput,
            "PiArchitectureImportBoundarySentry": ImportBoundaryOutput,
            "PiDepreciationScanner": DepreciationOutput,
            "PiDeadCodePruner": DeadCodeOutput,
            "PiMockDataTaintingSentry": MockDataTaintingOutput,
            "PiReadmeValidator": ReadmeOutput,
            "PiChangelogAuditor": ChangelogOutput,
            "PiAstDepthGuard": AstDepthOutput,
            "PiUncontrolledRecursionSentry": RecursionOutput,
            "PiMagicNumberScanner": MagicNumberOutput,
            "PiErrorHandlingCatchAllGuard": ErrorCatchOutput,
            "PiSemanticCommitMessageLinter": CommitLinterOutput,
            "PiWebVulnScanner": WebVulnOutput,
            "PiDeploymentSafetyGuard": DeploymentSafetyOutput,
            "PiPipelineIntegrityAuditor": PipelineIntegrityOutput
        }
        return mapping.get(agent_name)
