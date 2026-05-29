# src/pi_micro_agents/orchestrator/chain_engine.py
from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import re
import time
import traceback
from typing import Any, Dict, List, Type

_chain_logger = logging.getLogger("pi_chain_engine")

from pydantic import BaseModel

from pi_agent_chain.ledger import StateLedger
from pi_agent_chain.models import ExecutionTrace
from pi_micro_agents.orchestrator.consensus import run_with_consensus
from pi_micro_agents.orchestrator.router import AgentRoute, AgentRouter
from pi_micro_agents.orchestrator.shield import PiOrchestratorShield


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
            "container ingress": [
                "PiNginxReverseProxyHeaderSentry",
                "PiDockerComposeSecuritySentry",
                "PiDockerSocketPrivilegeSentry",
            ],
            "proxy defender": [
                "PiNginxReverseProxyHeaderSentry",
                "PiDockerComposeSecuritySentry",
                "PiDockerSocketPrivilegeSentry",
            ],
            "hallucination": ["PiLLMHallucinationDetector", "PiPromptLeakBuster", "PiLLMPromptEgressLeakDetector"],
            "leak buster": ["PiLLMHallucinationDetector", "PiPromptLeakBuster", "PiLLMPromptEgressLeakDetector"],
            "ci/cd release": ["PiGithubActionsUnpinnedVersion", "PiGitSafetyGuardrail", "PiChangelogAuditor"],
            "dependency alignment": ["PiGithubActionsUnpinnedVersion", "PiGitSafetyGuardrail", "PiChangelogAuditor"],
            "zk-circuit soundness": [
                "PiZKNonPrimeFieldRangeSentry",
                "PiZKSignalUnconstrainedConstraint",
                "PiZKUnusedConstraintVariables",
            ],
            "zk auditing": [
                "PiZKNonPrimeFieldRangeSentry",
                "PiZKSignalUnconstrainedConstraint",
                "PiZKUnusedConstraintVariables",
            ],
            "solana cpi": [
                "PiRustSolanaAccountDataValidation",
                "PiRustSolanaCPIInstructionSentry",
                "PiRustSolanaOwnerVerificationGuard",
            ],
            "solana cpi security": [
                "PiRustSolanaAccountDataValidation",
                "PiRustSolanaCPIInstructionSentry",
                "PiRustSolanaOwnerVerificationGuard",
            ],
            "database migration": [
                "PiMockDataTaintingSentry",
                "PiDatabaseMigrationUnindexedSentry",
                "PiTddMockingSanityChecker",
            ],
            "qa validation": [
                "PiMockDataTaintingSentry",
                "PiDatabaseMigrationUnindexedSentry",
                "PiTddMockingSanityChecker",
            ],
            # 20 New Playbooks Integration
            "web application vulnerability scanning": [
                "PiWebVulnScanner",
                "PiSelfHealingPatchAgent",
                "PiDeploymentSafetyGuard",
            ],
            "cloud cost optimization": ["PiCloudCostAnalyzer", "PiIdleResourceSentry", "PiBudgetAnomalyGuard"],
            "api security & rate limiting": [
                "PiAPIRateLimitSentry",
                "PiApiAuthHardcodedTokenSentry",
                "PiEndpointAbuseGuard",
            ],
            "database query optimization": [
                "PiSlowQueryDetector",
                "PiSQLInjectionSentry",
                "PiIndexRecommendationEngine",
            ],
            "container image security": [
                "PiDockerImageScanner",
                "PiDockerComposeSecuritySentry",
                "PiContainerEscapeDetector",
            ],
            "ci/cd pipeline integrity": [
                "PiGithubActionsUnpinnedVersion",
                "PiGitSecretLeakSentry",
                "PiPipelineIntegrityAuditor",
            ],
            "frontend supply chain": ["PiNPMDependencyVulnScanner", "PiGitSecScanner", "PiTreeShakingOptimizer"],
            "llm output sanitization": [
                "PiLLMOutputSanitizer",
                "PiLLMHallucinationDetector",
                "PiLLMPromptEgressLeakDetector",
            ],
            "data privacy compliance": ["PiDataFlowPrivacyMapper", "PiSensitiveDataScanner", "PiAutomatedAnonymizer"],
            "logging & observability anomaly": [
                "PiSensitiveLogLeakSentry",
                "PiGitSecretEntropyLeakSentry",
                "PiStructuredLoggingEnforcer",
            ],
            "access control & privilege escalation": [
                "PiIAMOverPermissionSentry",
                "PiAccessControlShadow",
                "PiLeastPrivilegeRemediator",
            ],
            "documentation & code comment consistency": [
                "PiDocsOutdatedChecker",
                "PiReadmeValidator",
                "PiAutoDocsGenerator",
            ],
            "performance profiling": ["PiMemoryLeakDetector", "PiHotPathAllocationAuditor", "PiBottleneckOptimizer"],
            "mobile app security": ["PiMobilePermissionSentry", "PiAppDataLeakDetector", "PiRuntimeHardeningGuard"],
            "network traffic analysis": ["PiNetworkTrafficSentry", "PiDDoSPatternDetector", "PiTrafficOptimizer"],
            "backup & disaster recovery": [
                "PiBackupIntegritySentry",
                "PiRecoveryTimeAuditor",
                "PiAutomatedRestoreTester",
            ],
            "accessibility & wcag compliance": [
                "PiAccessibilityScanner",
                "PiContrastRatioAuditor",
                "PiAutoRemediationEngine",
            ],
            "secrets management & rotation": [
                "PiHardcodedSecretDetector",
                "PiGitSecretLeakSentry",
                "PiAutomatedRotationEngine",
            ],
            "iac security & drift": [
                "PiTerraformDriftDetector",
                "PiTerraformStateCredentialSentry",
                "PiInfrastructureComplianceAuditor",
            ],
            "frontend performance & core web vitals": [
                "PiLighthouseAuditor",
                "PiBundleSizeSentry",
                "PiCoreWebVitalsOptimizer",
            ],
            # Antigravity IDE / Google AI tooling reverse engineering & audit playbooks
            "antigravity ide reverse engineering": [
                "PiMagicNumberScanner",
                "PiHardcodedSecretDetector",
                "PiApiReverseEngineeredAuth",
                "PiGrpcProtocolInterceptor",
                "PiDependencyVulnScanner",
                "PiThreatModelGenerator",
                "PiRuntimeAnomalySentry",
                "PiSensitiveLogLeakSentry",
                "PiAuditLogTamperDetector",
            ],
            "antigravity re": [
                "PiMagicNumberScanner",
                "PiHardcodedSecretDetector",
                "PiApiReverseEngineeredAuth",
                "PiGrpcProtocolInterceptor",
                "PiDependencyVulnScanner",
                "PiThreatModelGenerator",
                "PiRuntimeAnomalySentry",
            ],
            "ide language server audit": [
                "PiGrpcProtocolInterceptor",
                "PiGrpcWireProtocolInsecureSentry",
                "PiApiReverseEngineeredAuth",
                "PiRuntimeAnomalySentry",
                "PiThreatModelGenerator",
            ],
            "binary ide surface": [
                "PiMagicNumberScanner",
                "PiHardcodedSecretDetector",
                "PiDependencyVulnScanner",
                "PiThreatModelGenerator",
            ],
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
            "PiSelfHealingPatchAgent": {
                "heal",
                "healer",
                "patch",
                "repair",
                "remediate",
                "remediation",
                "self-heal",
                "fix",
            },
            "PiArithmeticAuditor": {"arithmetic", "math", "overflow", "underflow", "rounding", "precision"},
            "PiReentrancySentry": {"reentrancy", "checks-effects", "mutex", "reentrant"},
            "PiDeFiSlippageGuard": {"slippage", "swap", "mev", "sandwich", "frontrun"},
            "PiOracleDivergenceAudit": {"oracle", "divergence", "price feed", "stale"},
            "PiStorageLayoutDrift": {"storage layout", "drift", "gap", "upgradeable", "initializer", "collision"},
            "PiTokenTaxDetector": {"token tax", "fee-on-transfer", "honeypot", "tax"},
            "PiCentralizationSentry": {"centralization", "multisig", "timelock", "admin", "privilege"},
            "PiPublisherDispatch": {"publish", "deploy", "dispatch", "commit"},
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
            "PiPublisherDispatch": 5,
        }

        task_indicators = {
            "scan",
            "scanner",
            "check",
            "checker",
            "audit",
            "auditor",
            "heal",
            "healer",
            "patch",
            "repair",
            "remediate",
            "fix",
            "verify",
            "verifier",
            "sentry",
            "guard",
            "deploy",
            "publish",
            "run",
            "test",
            "linter",
            "scout",
            "hunter",
            "shield",
            "protect",
        }
        matched_agent_names = []

        for idx, sub_task in enumerate(sub_tasks):
            # Check if this sub-task is valid (is first, or contains at least one task indicator verb)
            sub_tokens = set(re.findall(r"[a-zA-Z0-9]+", sub_task))
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
            # Word-boundary match rather than substring — prevents "reentrant"
            # from over-matching "reentracy" (and similar near-collisions).
            agent_lc = route.agent_name.lower()
            class_lc = route.agent_class.__name__.lower()
            if re.search(rf"\b{re.escape(name_clean)}\b", agent_lc) or re.search(
                rf"\b{re.escape(name_clean)}\b", class_lc
            ):
                return route
        # Keyword match fallback (also word-bounded)
        for route in AgentRouter.routes:
            if any(re.search(rf"\b{re.escape(kw)}\b", name_clean) for kw in route.keywords):
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
        global_context: Dict[str, Any],
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
                    ctx["vulnerable_lines"] = sorted(set(lines))
                else:
                    # Don't fabricate line numbers — downstream agents read
                    # this as "no specific location known" and act accordingly.
                    ctx["vulnerable_lines"] = []
                ctx["vulnerability_type"] = vuln_type

        # Instantiate input envelope using route's input factory
        input_envelope = target_route.input_factory(goal, ctx)

        # Secure attribute-level fallback override. We build an `updates` dict
        # and apply via model_copy(update=...) which re-runs Pydantic
        # validation — a raw setattr would let untyped context values
        # silently land on typed fields.
        updates: Dict[str, Any] = {}
        for field_name in input_envelope.model_fields.keys():
            current_val = getattr(input_envelope, field_name, None)
            if current_val is not None and current_val != "" and current_val != []:
                continue
            if field_name in ctx:
                updates[field_name] = ctx[field_name]
            elif field_name == "solidity_code" and "source_code" in ctx:
                updates[field_name] = ctx["source_code"]
            elif field_name == "source_code" and "solidity_code" in ctx:
                updates[field_name] = ctx["solidity_code"]

        if updates:
            try:
                input_envelope = input_envelope.__class__.model_validate({**input_envelope.model_dump(), **updates})
            except Exception as e:
                _chain_logger.warning(
                    "Context fallback rejected by Pydantic validation for %s: %s",
                    target_route.agent_name,
                    e,
                )

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
        deadline_exceeded = False

        try:
            chain_timeout_s = float(os.getenv("PI_CHAIN_EXECUTION_TIMEOUT_SECONDS", "300"))
        except ValueError:
            chain_timeout_s = 300.0
        chain_start = time.perf_counter()

        for idx, route in enumerate(routes):
            elapsed_s = time.perf_counter() - chain_start
            if chain_timeout_s > 0 and elapsed_s >= chain_timeout_s:
                _chain_logger.warning(
                    "Chain execution timeout (%.1fs >= %.1fs) before step %d (%s); halting.",
                    elapsed_s,
                    chain_timeout_s,
                    idx + 1,
                    route.agent_name,
                )
                chain_success = False
                deadline_exceeded = True
                step_receipts.append(
                    {
                        "step_index": idx + 1,
                        "agent_name": route.agent_name,
                        "success": False,
                        "risk_score": 0.0,
                        "latency_ms": 0.0,
                        "summary": "skipped: chain deadline exceeded",
                        "details": {"deadline_exceeded": True, "elapsed_s": elapsed_s, "timeout_s": chain_timeout_s},
                        "alerts": ["chain_deadline_exceeded"],
                        "consensus_telemetry": {},
                    }
                )
                break

            start_step = time.perf_counter()

            # 1. Map Inputs
            prev_out_dict = copy.deepcopy(prev_output.model_dump()) if prev_output else {}
            input_envelope = SchemaParameterMapper.map_output_to_input(
                prev_output, route, goal, {**context, **prev_out_dict}
            )

            # 2. Strict Ingress safety checks on mapped input/context
            step_ctx = {**prev_out_dict, **context}

            # Check defensive-only
            if defensive_only or PiOrchestratorShield.check_defensive_only(step_ctx):
                raise ValueError(
                    "Blocked: Defensive-only execution mode rejects shell commands/code execution payloads."
                )

            # Command Safety
            cmd_viol = PiOrchestratorShield.check_command_safety(step_ctx)
            if cmd_viol and is_strict:
                raise ValueError(f"Blocked: Proposed shell command triggers active safety gate: {cmd_viol[1]}")

            # AST Safety
            if route.agent_name not in [
                "PiGitSecScanner",
                "PiSelfHealingPatchAgent",
                "PiReentrancySentry",
                "PiAccessControlVerifier",
                "PiFlashLoanDefender",
                "PiArithmeticAuditor",
                "PiDelegateCallGuard",
                "PiSignatureReplayScout",
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
                "PiStorageLayoutDrift",
                "PiERC4626VaultGuard",
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
            ]:
                ast_viols = PiOrchestratorShield.check_ast_safety(step_ctx)
                if ast_viols and is_strict:
                    raise ValueError(
                        f"Blocked: Proposed Python code contains forbidden structures: {', '.join(ast_viols)}"
                    )

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
            consensus_telemetry.get("votes", [])

            # Construct clean output matching agent's class output
            prev_output = None  # cleared; will be set to output class or left None
            try:
                out_cls = self._resolve_output_class(route.agent_name)
                if out_cls:
                    prev_output = out_cls(**details)
            except Exception:
                _chain_logger.error(
                    "Output class instantiation failed for %s at step %d: %s",
                    route.agent_name,
                    idx + 1,
                    traceback.format_exc(),
                )

            # 4. Commit Independent Execution Trace to SQLite StateLedger
            trace_id = (
                "trace_chain_step_" + hashlib.sha256(f"{route.agent_name}_{time.time()}".encode()).hexdigest()[:12]
            )
            payload_hash = hashlib.sha256(input_envelope.model_dump_json().encode()).hexdigest()

            trace = ExecutionTrace(
                trace_id=trace_id,
                node_name=route.agent_name,
                input_payload_hash=payload_hash,
                llm_seed=1337,
                llm_temperature=0.0,
                raw_output=json.dumps(details),
                is_valid_type=success,
                error_message=", ".join(alerts) if alerts else None,
            )
            self.ledger.append(trace)

            step_receipts.append(
                {
                    "step_index": idx + 1,
                    "agent_name": route.agent_name,
                    "success": success,
                    "risk_score": risk_score,
                    "latency_ms": step_latency,
                    "summary": summary,
                    "details": details,
                    "alerts": alerts,
                    "consensus_telemetry": consensus_telemetry,
                }
            )

            # Check strict mode gating for vulnerabilities found by the agent or direct step failure
            if not success or (is_strict and risk_score >= 80.0):
                chain_success = False
                break

        # prev_output can be None when the last step's output class couldn't
        # be instantiated (line 481). Guard before .model_dump().
        if prev_output is None:
            final_details: Dict[str, Any] = {}
        elif hasattr(prev_output, "model_dump"):
            final_details = prev_output.model_dump()
        else:
            try:
                final_details = dict(prev_output)
            except (TypeError, ValueError):
                final_details = {}

        return {
            "success": chain_success,
            "chain_receipts": step_receipts,
            "total_latency_ms": sum(latencies),
            "average_latency_ms": sum(latencies) / len(latencies) if latencies else 0.0,
            "deadline_exceeded": deadline_exceeded,
            "chain_timeout_s": chain_timeout_s,
            "chain_elapsed_s": time.perf_counter() - chain_start,
            "final_details": final_details,
        }

    def _resolve_output_class(self, agent_name: str) -> Type[BaseModel] | None:
        from pi_micro_agents.orchestrator.consensus import (
            AccessControlOutput,
            AgentToolGuardOutput,
            ArbitrageOutput,
            ArithmeticOutput,
            AssemblySafetyOutput,
            AstDepthOutput,
            BlockTimestampOutput,
            BridgeAuditOutput,
            BytecodeDecompilerOutput,
            CavemanCompressorOutput,
            CentralizationOutput,
            ChangelogOutput,
            CommitLinterOutput,
            ConstantTimeOutput,
            DeadCodeOutput,
            DeFiSlippageOutput,
            DepreciationOutput,
            DesignAnInterfaceOutput,
            DimensionalAnalysisOutput,
            DoSGasLimitsOutput,
            ErrorCatchOutput,
            ExternalContractGuardOutput,
            FlashLoanOutput,
            GasGuzzlerOutput,
            GitSafetyOutput,
            GitSecOutput,
            GrillMeOutput,
            HandoffOutput,
            HotPathAllocationOutput,
            ImportBoundaryOutput,
            LogicGatekeeperOutput,
            MagicNumberOutput,
            MemoryZeroizeOutput,
            MempoolTxOutput,
            MockDataTaintingOutput,
            OracleDivergenceOutput,
            OracleSentryOutput,
            PhishingShieldOutput,
            PragmaSentryOutput,
            PublisherOutput,
            ReadmeOutput,
            ReadOnlyReentrancyOutput,
            RecursionOutput,
            ReentrancyOutput,
            RequestRefactorOutput,
            SelfDestructHunterOutput,
            SelfHealingOutput,
            ShadowedVariableOutput,
            StorageDriftOutput,
            TddAssertionOutput,
            TddMockingOutput,
            TddTestFileOutput,
            ToIssuesOutput,
            TokenTaxOutput,
            ToPrdOutput,
            TriageOutput,
            TxOriginOutput,
            TypeScriptWizardryOutput,
            UninitializedOutput,
            UpgradeDefectOutput,
            VaultGuardOutput,
            VyperScannerOutput,
            ZoomOutOutput,
        )
        from pi_micro_agents.pi_api_owasp_scanner import APIOutput
        from pi_micro_agents.pi_audit_log_tamper_detector import LogOutput
        from pi_micro_agents.pi_automated_anonymizer import AnonymizerOutput
        from pi_micro_agents.pi_automated_rotation_engine import RotationOutput
        from pi_micro_agents.pi_backup_integrity_checker import BackupOutput
        from pi_micro_agents.pi_certificate_rotation_watcher import CertOutput
        from pi_micro_agents.pi_cloud_config_auditor import CloudConfigOutput
        from pi_micro_agents.pi_code_signing_enforcer import SigningOutput
        from pi_micro_agents.pi_container_escape_detector import ContainerEscapeOutput
        from pi_micro_agents.pi_data_flow_privacy_mapper import PrivacyMapperOutput
        from pi_micro_agents.pi_data_retention_policy_enforcer import RetentionOutput
        from pi_micro_agents.pi_dependency_vuln_scanner import DependencyOutput
        from pi_micro_agents.pi_deployment_safety_guard import DeploymentSafetyOutput
        from pi_micro_agents.pi_docker_image_scanner import DockerImageOutput
        from pi_micro_agents.pi_encryption_compliance_checker import EncryptionOutput
        from pi_micro_agents.pi_firewall_rule_auditor import FirewallOutput
        from pi_micro_agents.pi_hardcoded_secret_detector import HardcodedSecretOutput
        from pi_micro_agents.pi_iac_scanner import IaCOutput
        from pi_micro_agents.pi_kubernetes_security_auditor import K8sOutput
        from pi_micro_agents.pi_llm_output_sanitizer import LLMOutputSanitizerOutput
        from pi_micro_agents.pi_misconfig_pattern_matcher import MisconfigOutput
        from pi_micro_agents.pi_pipeline_integrity_auditor import PipelineIntegrityOutput
        from pi_micro_agents.pi_rbac_permission_mapper import RBACOutput
        from pi_micro_agents.pi_runtime_anomaly_sentry import AnomalyOutput
        from pi_micro_agents.pi_sbom_validator import SBOMOutput
        from pi_micro_agents.pi_secrets_manager_completeness_checker import VaultOutput
        from pi_micro_agents.pi_sensitive_data_scanner import SensitiveDataOutput
        from pi_micro_agents.pi_sensitive_log_leak_sentry import LogLeakOutput
        from pi_micro_agents.pi_structured_logging_enforcer import StructuredLoggingOutput
        from pi_micro_agents.pi_supply_chain_integrity_checker import SupplyChainOutput
        from pi_micro_agents.pi_threat_model_generator import ThreatModelOutput
        from pi_micro_agents.pi_web_vuln_scanner import WebVulnOutput
        from pi_micro_agents.pi_zero_trust_verifier import ZeroTrustOutput

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
            "PiPipelineIntegrityAuditor": PipelineIntegrityOutput,
            "PiDockerImageScanner": DockerImageOutput,
            "PiContainerEscapeDetector": ContainerEscapeOutput,
            "PiHardcodedSecretDetector": HardcodedSecretOutput,
            "PiAutomatedRotationEngine": RotationOutput,
            "PiLLMOutputSanitizer": LLMOutputSanitizerOutput,
            "PiDataFlowPrivacyMapper": PrivacyMapperOutput,
            "PiSensitiveDataScanner": SensitiveDataOutput,
            "PiAutomatedAnonymizer": AnonymizerOutput,
            "PiSensitiveLogLeakSentry": LogLeakOutput,
            "PiStructuredLoggingEnforcer": StructuredLoggingOutput,
            "PiIaCScanner": IaCOutput,
            "PiDependencyVulnScanner": DependencyOutput,
            "PiCloudConfigAuditor": CloudConfigOutput,
            "PiRBACPermissionMapper": RBACOutput,
            "PiEncryptionComplianceChecker": EncryptionOutput,
            "PiSBOMValidator": SBOMOutput,
            "PiSupplyChainIntegrityChecker": SupplyChainOutput,
            "PiAPIOWASPScanner": APIOutput,
            "PiKubernetesSecurityAuditor": K8sOutput,
            "PiZeroTrustVerifier": ZeroTrustOutput,
            "PiCertificateRotationWatcher": CertOutput,
            "PiFirewallRuleAuditor": FirewallOutput,
            "PiBackupIntegrityChecker": BackupOutput,
            "PiAuditLogTamperDetector": LogOutput,
            "PiMisconfigPatternMatcher": MisconfigOutput,
            "PiThreatModelGenerator": ThreatModelOutput,
            "PiSecretsManagerCompletenessChecker": VaultOutput,
            "PiCodeSigningEnforcer": SigningOutput,
            "PiDataRetentionPolicyEnforcer": RetentionOutput,
            "PiRuntimeAnomalySentry": AnomalyOutput,
        }
        return mapping.get(agent_name)
