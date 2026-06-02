from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
from datetime import datetime
from typing import Any, Dict, List

from pydantic import BaseModel, Field

from pi_agent_chain.ledger import StateLedger
from pi_agent_chain.models import ExecutionTrace
from pi_agent_chain.tenant_context import current_tenant
from pi_micro_agents.orchestrator.consensus import run_with_consensus
from pi_micro_agents.orchestrator.router import AgentRouter

# Modular imports
from pi_micro_agents.orchestrator.shield import PiOrchestratorShield
from pi_micro_agents.pi_curation_stylist import CurationInput, PiCurationStylist

# Specialized pipeline micro-agents imports
from pi_micro_agents.pi_niche_scraper import PiNicheScraper, ScraperInput
from pi_micro_agents.pi_publisher_dispatch import PiPublisherDispatch, PublisherInput
from pi_micro_agents.pi_spend_hunter import PiSpendAnomalyHunter
from pi_micro_agents.pi_youtube_transcriber import PiYoutubeTranscriber, TranscriptInput


def is_strict_mode() -> bool:
    """Strict mode resolver checking environment variables and configuration files."""
    env_val = os.getenv("PI_ORCHESTRATOR_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_ORCHESTRATOR_STRICT_MODE", True))
        except Exception:
            pass
    return True


class OrchestratorInput(BaseModel):
    goal: str = Field(..., description="The natural language task goal to execute")
    context: Dict[str, Any] = Field(default_factory=dict, description="Context variables required for execution")


class OrchestratorOutput(BaseModel):
    success: bool = Field(..., description="Indicates whether the orchestration goal was completed successfully")
    routed_agent: str = Field(..., description="The micro-agent or pipeline chain selected to resolve the goal")
    risk_score: float = Field(
        ..., description="The highest calculated safety/vulnerability risk score across the chain"
    )
    output_summary: str = Field(..., description="Human-readable execution completion summary")
    result_details: Dict[str, Any] = Field(
        default_factory=dict, description="Specific details returned by the executed agent"
    )
    anomalies_detected: List[str] = Field(
        default_factory=list, description="List of any injection, leak, or cost violations caught"
    )


class PiOrchestrator:
    """Master generalist orchestrator that dynamically safety-checks, routes, and logs natural language goals."""

    def __init__(self, ledger: StateLedger | None = None) -> None:
        self.agent_name = "PiOrchestrator"
        self.ledger = ledger or StateLedger(":memory:")

    def _tokenize(self, text: str) -> List[str]:
        return re.findall(r"[a-zA-Z0-9]+", text.lower())

    def _calculate_similarity(self, tokens_goal: List[str], tokens_doc: List[str]) -> float:
        if not tokens_goal or not tokens_doc:
            return 0.0
        vocab = set(tokens_goal).union(set(tokens_doc))
        vec_goal = {w: tokens_goal.count(w) for w in vocab}
        vec_doc = {w: tokens_doc.count(w) for w in vocab}

        dot_product = sum(vec_goal[w] * vec_doc[w] for w in vocab)
        mag_goal = sum(vec_goal[w] ** 2 for w in vocab) ** 0.5
        mag_doc = sum(vec_doc[w] ** 2 for w in vocab) ** 0.5

        if mag_goal == 0.0 or mag_doc == 0.0:
            return 0.0
        return dot_product / (mag_goal * mag_doc)

    def augment_context_via_rag(self, goal: str) -> Dict[str, Any]:
        """Auto-enrich execution context by matching natural-language goals against the local Obsidian Wiki vault using cosine similarity."""
        rag_context: Dict[str, Any] = {}

        # 1. Locate Obsidian Wiki directories (PI-Platform + the dedicated vault/).
        # Resolved relative to the package or CWD — NOT a hardcoded developer home
        # path (the old "/Users/clubpenguin/..." entry only existed on one machine,
        # so RAG enrichment silently no-op'd everywhere else). Override with
        # PI_RAG_VAULT_DIR.
        candidate_vaults = [
            os.environ.get("PI_RAG_VAULT_DIR", ""),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../PI-Platform")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "../../vault")),
            "vault",
        ]

        vault_dir = None
        for cand in candidate_vaults:
            if os.path.exists(cand) and os.path.isdir(cand):
                vault_dir = cand
                break

        if not vault_dir:
            return rag_context

        # 2. Find all markdown files and calculate cosine similarity
        best_doc_path = None
        best_similarity = 0.0
        best_doc_content = ""

        goal_tokens = self._tokenize(goal)
        if not goal_tokens:
            return rag_context

        for entry in list(os.scandir(vault_dir)):  # snapshot prevents issues with concurrent writes
            if not entry.name.endswith(".md"):
                continue
            file_path = entry.path
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                doc_tokens = self._tokenize(entry.name.replace(".md", " ") + " " + content)
                sim = self._calculate_similarity(goal_tokens, doc_tokens)

                if sim > best_similarity:
                    best_similarity = sim
                    best_doc_path = file_path
                    best_doc_content = content
            except (OSError, UnicodeDecodeError) as e:
                logging.getLogger("pi_orchestrator").warning("RAG vault read failed for %s: %s", file_path, e)

        # 3. Extract parameter options if similarity is above a threshold
        if best_doc_path and best_similarity > 0.05:
            # Extract generic options from JSON blocks first
            json_blocks = re.findall(r"```json\s*(\{.*?\})\s*```", best_doc_content, re.DOTALL)
            for block in json_blocks:
                try:
                    data = json.loads(block)
                    if isinstance(data, dict):
                        for key in ["niche", "spend_limit", "max_items", "draft_only"]:
                            if key in data:
                                rag_context[key] = data[key]
                        if "target_handles" in data and isinstance(data["target_handles"], list):
                            handles = [h.replace("@", "").lower() for h in data["target_handles"]]
                            rag_context["target_handles"] = handles
                except Exception:
                    pass

            # Specialize based on known pipelines and keyword matchers
            goal_lower = goal.lower()

            # Creators mapping
            known_creators = ["karpathy", "levelsio", "jackbutcher", "robertmiles"]
            matched_creators = []
            for creator in known_creators:
                if creator in goal_lower:
                    matched_creators.append(creator)
            if matched_creators:
                rag_context["creators"] = matched_creators

            # Niche mapping
            known_niches = ["ai", "defi", "rust", "crypto"]
            for niche in known_niches:
                if niche in goal_lower:
                    rag_context["niche"] = niche.upper() if niche != "rust" else "Rust"

            # Spend limit mapping from goal
            spend_match = re.search(r"(?:spend[-_]limit|budget|limit)\s*(?:of\s*)?\$?([0-9]+(?:\.[0-9]+)?)", goal_lower)
            if spend_match:
                try:
                    rag_context["spend_limit"] = float(spend_match.group(1))
                except ValueError:
                    pass

            # Draft-only mapping
            if "draft" in goal_lower:
                rag_context["draft_only"] = True
            elif "publish live" in goal_lower or "no draft" in goal_lower:
                rag_context["draft_only"] = False

        return rag_context

    def execute_goal(self, input_envelope: OrchestratorInput) -> OrchestratorOutput:
        goal = input_envelope.goal

        # RAG Context Enrichment via local Obsidian vault
        rag_context = self.augment_context_via_rag(goal)
        # Merge RAG context with input context
        context = {**rag_context, **input_envelope.context}

        anomalies: List[str] = []
        is_strict = is_strict_mode()

        # Step 0.5: Defensive-only check
        if PiOrchestratorShield.check_defensive_only(context):
            return self._compile_and_log_output(
                success=False,
                routed_agent="PIGovernShield",
                risk_score=100.0,
                summary="Blocked: Defensive-only runtime mode rejects any proposed shell commands or python script payloads.",
                details={},
                anomalies=["Defensive-only violation: execution payload rejected."],
                goal=goal,
            )

        # Step 1: Prompt Shield Check
        injection_risk, injection_viols = PiOrchestratorShield.check_prompt_injection(goal)
        if injection_risk >= 70.0:
            anomalies.extend(injection_viols)
            if is_strict:
                return self._compile_and_log_output(
                    success=False,
                    routed_agent="PiPromptShield",
                    risk_score=injection_risk,
                    summary=f"Blocked: Prompt injection or jailbreak detected in goal: {', '.join(injection_viols)}",
                    details={},
                    anomalies=anomalies,
                    goal=goal,
                )

        # Step 2: Spend/Cost Hunter Check
        spend_hunter = PiSpendAnomalyHunter()
        messages = [{"role": "user", "content": goal}]
        spend_status, _ = spend_hunter.check_request(messages)
        if spend_status in ["BLOCKED_PROMPT_BLOAT", "BLOCKED_SPEND_LIMIT_EXCEEDED"]:
            anomalies.append(f"Spend violation: {spend_status}")
            if is_strict:
                return self._compile_and_log_output(
                    success=False,
                    routed_agent="PiSpendAnomalyHunter",
                    risk_score=90.0,
                    summary=f"Blocked: Cost/budget anomaly hunter tripped: {spend_status}",
                    details={},
                    anomalies=anomalies,
                    goal=goal,
                )

        # Step 2.5: PI Interceptor Proxy Governance Shield
        start_routing = time.perf_counter()

        # Intercept and compile dynamic multi-agent execution chain first
        from pi_micro_agents.orchestrator.chain_engine import AgentChainCompiler, ChainExecutionEngine

        chain_routes = AgentChainCompiler.compile_chain(goal, context)

        routed_route = AgentRouter.resolve(goal, context)
        routing_latency = (time.perf_counter() - start_routing) * 1000
        target_agent = routed_route.agent_name if routed_route else "PiMasterGeneralistFallback"

        # Check for proposed shell commands in context
        cmd_violation = PiOrchestratorShield.check_command_safety(context)
        if cmd_violation:
            cmd_risk, cmd_candidate = cmd_violation
            anomalies.append(f"Command security violation: High risk command detected (Risk: {cmd_risk})")
            if is_strict:
                return self._compile_and_log_output(
                    success=False,
                    routed_agent="PIGovernShield",
                    risk_score=cmd_risk,
                    summary=f"Blocked: Proposed shell command triggers safety gate: {cmd_candidate}",
                    details={},
                    anomalies=anomalies,
                    goal=goal,
                )

        # Check for proposed Python script contents
        if len(chain_routes) < 2 and target_agent not in [
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
            # Cohort 11 Agents
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
        ]:
            ast_violations = PiOrchestratorShield.check_ast_safety(context)
            if ast_violations:
                anomalies.extend(ast_violations)
                if is_strict:
                    return self._compile_and_log_output(
                        success=False,
                        routed_agent="PIGovernShield",
                        risk_score=90.0,
                        summary=f"Blocked: Proposed Python code contains forbidden structures: {', '.join(ast_violations)}",
                        details={},
                        anomalies=anomalies,
                        goal=goal,
                    )

        # Step 3: Semantic Intent Routing Decision
        start_execution = time.perf_counter()
        routed_agent = "PiMasterGeneralistFallback"
        success = True
        risk_score = 0.0
        output_summary = "Goal processed by generalist executor."
        result_details: Dict[str, Any] = {}

        # Intercept and run dynamic multi-agent execution chain if compiled
        if len(chain_routes) >= 2:
            chain_engine = ChainExecutionEngine(self, self.ledger)
            try:
                chain_result = chain_engine.execute_chain(chain_routes, goal, context)
                chain_success = chain_result["success"]
                chain_risk = (
                    max(step["risk_score"] for step in chain_result["chain_receipts"])
                    if chain_result["chain_receipts"]
                    else 0.0
                )
                chain_agent_str = " -> ".join([r.agent_name for r in chain_routes])
                chain_summary = f"Multi-agent chain completed successfully: {chain_agent_str}"

                # Collect step anomalies
                for step in chain_result["chain_receipts"]:
                    alerts = step.get("alerts") or []
                    for alt in alerts:
                        if alt not in anomalies:
                            anomalies.append(alt)

                res_details = {
                    **chain_result["final_details"],
                    "chain_receipts": chain_result["chain_receipts"],
                    "_latency_metrics": {
                        "routing_ms": routing_latency,
                        "execution_ms": chain_result["total_latency_ms"],
                    },
                }

                return self._compile_and_log_output(
                    success=chain_success,
                    routed_agent=chain_agent_str,
                    risk_score=chain_risk,
                    summary=chain_summary,
                    details=res_details,
                    anomalies=anomalies,
                    goal=goal,
                )
            except Exception as e:
                chain_agent_str = " -> ".join([r.agent_name for r in chain_routes])
                anomalies.append(f"Chain execution error: {str(e)}")
                return self._compile_and_log_output(
                    success=False,
                    routed_agent=chain_agent_str,
                    risk_score=100.0,
                    summary=f"Chain execution failed: {str(e)}",
                    details={},
                    anomalies=anomalies,
                    goal=goal,
                )

        if routed_route:
            routed_agent = routed_route.agent_name

            # Route C: Niche Content Curation and Publishing Pipeline
            if routed_route.agent_name == "NicheCurationPipelineChain":
                niche = context.get("niche", "AI")
                draft_only = context.get("draft_only", True)
                creators = context.get("creators", ["karpathy", "levelsio", "jackbutcher", "robertmiles"])
                video_urls = context.get("video_urls", [])

                # Run Scraper (Agent 1)
                scraper = PiNicheScraper()
                scrap_out = scraper.scrape_niche(ScraperInput(niche=niche))

                # Run Transcriber (Agent 1.5)
                transcripts = []
                transcriber = PiYoutubeTranscriber()
                for c in creators:
                    c_urls = video_urls or [f"https://www.youtube.com/watch?v={c}_v1"]
                    trans_out = transcriber.transcribe_videos(TranscriptInput(video_urls=c_urls, creator=c))
                    if trans_out.success:
                        for item in trans_out.transcripts:
                            transcripts.append(f"[{c.upper()} YouTube Video {item.video_id}]: {item.text}")

                # Run Stylist (Agent 2)
                stylist = PiCurationStylist()
                style_out = stylist.format_newsletter(
                    CurationInput(
                        niche=niche,
                        tweets=scrap_out.tweets,
                        github_repos=scrap_out.github_repos,
                        transcripts=transcripts,
                    )
                )

                # Run Publisher (Agent 3)
                pub_inp = PublisherInput(
                    substack_title=style_out.substack_title,
                    substack_markdown_body=style_out.substack_markdown_body,
                    x_thread_posts=style_out.x_thread_posts,
                    draft_only=draft_only,
                )
                pub_success, pub_risk_score, pub_summary, pub_details, pub_alerts = run_with_consensus(
                    self, PiPublisherDispatch, pub_inp, goal, context, "PiPublisherDispatch"
                )

                success = pub_success
                risk_score = pub_risk_score
                output_summary = pub_summary
                result_details = pub_details
                anomalies.extend(pub_alerts)

            # Route B: Outbound Data Leak Scanning
            elif routed_route.agent_name == "PiPromptLeakBuster":
                buster = routed_route.agent_class()
                inp_env = routed_route.input_factory(goal, context)
                res = buster.scan_text(inp_env)
                success = res.is_secure
                risk_score = res.risk_score
                output_summary = f"Completed egress leak audit. Status: {res.status}"
                result_details = res.model_dump()
                anomalies.extend(res.flagged_leaks)

            # All other routes
            else:
                inp_env = routed_route.input_factory(goal, context)
                success, risk_score, output_summary, result_details, alerts = run_with_consensus(
                    self, routed_route.agent_class, inp_env, goal, context, routed_agent
                )
                anomalies.extend(alerts)

        # Route Fallback: Standard response
        else:
            output_summary = "Goal parsed under Master Orchestrator fallback generalist mode."
            result_details = {"processed_at": datetime.utcnow().isoformat(), "goal": goal}

        # Step 4: Gating and Compile Egress Output
        if is_strict and risk_score >= 80.0:
            success = False

        # Inject latency metrics
        execution_latency = (time.perf_counter() - start_execution) * 1000
        result_details["_latency_metrics"] = {"routing_ms": routing_latency, "execution_ms": execution_latency}

        return self._compile_and_log_output(
            success=success,
            routed_agent=routed_agent,
            risk_score=risk_score,
            summary=output_summary,
            details=result_details,
            anomalies=anomalies,
            goal=goal,
        )

    def _compile_and_log_output(
        self,
        success: bool,
        routed_agent: str,
        risk_score: float,
        summary: str,
        details: Dict[str, Any],
        anomalies: List[str],
        goal: str,
    ) -> OrchestratorOutput:
        """Helper to serialize logs, hash payload, commit trace to StateLedger, and compile return object."""
        res_output = OrchestratorOutput(
            success=success,
            routed_agent=routed_agent,
            risk_score=risk_score,
            output_summary=summary,
            result_details=details,
            anomalies_detected=anomalies,
        )

        payload_hash = hashlib.sha256(goal.encode("utf-8")).hexdigest()
        trace_id = "trace_orch_" + hashlib.sha256(datetime.utcnow().isoformat().encode()).hexdigest()[:12]

        try:
            trace = ExecutionTrace(
                trace_id=trace_id,
                node_name=self.agent_name,
                input_payload_hash=payload_hash,
                llm_seed=1337,
                llm_temperature=0.0,
                raw_output=res_output.model_dump_json(),
                is_valid_type=success,
                error_message=", ".join(anomalies) if anomalies else None,
                tenant_id=current_tenant(),
            )
            self.ledger.append(trace)
        except Exception:
            pass

        return res_output
