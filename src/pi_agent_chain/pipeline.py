"""Deterministic Pipeline Driver for pi-semantic-recon.

Thin execution coordinator.
ALL node boundaries are kernel-mediated.
No worker communicates directly with another worker.

The governance kernel owns:
- transition legality
- schema validation
- entropy enforcement
- objective integrity
- replay metadata
- state advancement
- failure handling
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional

from pi_agent_chain.artifact_registry import ArtifactRegistry, SemanticArtifact
from pi_agent_chain.governance.kernel import GovernanceKernel
from pi_agent_chain.ledger import StateLedger
from pi_agent_chain.models import (
    DependencyGraph,
    EpistemicState,
    EquivalenceClass,
    ExecutionTrace,
    ExtractedProtocolSkeleton,
    GovernanceConfig,
    GovernanceViolation,
    GovernedPacket,
    NormalizedTrafficPacket,
    RuntimeState,
    SemanticDiff,
    SemanticIRTrace,
    SynthesizedSpec,
    ValidationBoundsConfig,
    VerificationReport,
    WorkerResponse,
    WorkerStatus,
)
from pi_agent_chain.nodes.acquisition_gateway import AcquisitionGatewayNode
from pi_agent_chain.nodes.flow_mapper import FlowMapperNode
from pi_agent_chain.nodes.semantic_typer import SemanticTyperNode
from pi_agent_chain.nodes.spec_synthesizer import SpecSynthesizerNode
from pi_agent_chain.nodes.structural_extractor import StructuralExtractorNode
from pi_agent_chain.nodes.verifier import DifferentialVerifierNode
from pi_agent_chain.verification.auth_consistency import AuthConsistencyValidator
from pi_agent_chain.verification.entropy_analysis import EntropyAnalysisValidator
from pi_agent_chain.verification.provenance_validator import ProvenanceValidator
from pi_agent_chain.verification.replay_validator import ReplayValidator
from pi_agent_chain.verification.semantic_quorum import SemanticQuorum
from pi_agent_chain.verification.state_transition import StateTransitionValidator


class PipelineDriver:
    """Run the pi-semantic-recon DAG under full governance kernel mediation."""

    def __init__(
        self,
        ledger: StateLedger,
        base_url: str,
        config: Optional[GovernanceConfig] = None,
        registry_path: str = ":memory:",
        bounds: Optional[Any] = None,
    ) -> None:
        self.ledger = ledger
        self.base_url = base_url
        self.config = config or GovernanceConfig()
        self.bounds = bounds or ValidationBoundsConfig()
        self.registry = ArtifactRegistry(registry_path)
        self.provenance_validator = ProvenanceValidator(self.registry, bounds=self.bounds)
        self.replay_validator = ReplayValidator()
        self.auth_validator = AuthConsistencyValidator(bounds=self.bounds)
        self.state_validator = StateTransitionValidator(bounds=self.bounds)
        self.semantic_quorum = SemanticQuorum(bounds=self.bounds)
        self.entropy_analyzer = EntropyAnalysisValidator(bounds=self.bounds)

        # Workers are stateless transforms. The kernel owns execution.
        self.acquirer = AcquisitionGatewayNode(source="MANUAL")
        self.extractor = StructuralExtractorNode()
        self.typer = SemanticTyperNode(
            confidence_threshold=self.config.semantic_confidence_threshold
        )
        self.mapper = FlowMapperNode()
        self.synthesizer = SpecSynthesizerNode()
        self.verifier = DifferentialVerifierNode(
            base_url=base_url,
            seed=self.config.verification_replay_seed,
        )

    def run(
        self,
        raw_traffic_pairs: List[tuple[str, str]],
        trace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute the full pipeline under kernel mediation.

        Every node boundary crosses through GovernanceKernel.execute().
        No worker-to-worker direct communication.
        """
        trace_id = trace_id or str(uuid.uuid4())

        # Initialize governance kernel for this pipeline run
        kernel = GovernanceKernel(
            root_goal_id=trace_id,
            objective_scope={
                "domain": self.base_url,
                "mode": "passive_protocol_analysis",
                "trace_id": trace_id,
            },
            config=self.config,
        )

        # --- Initialize: REGISTERED -> SCOPED -> CAPTURE_READY ---
        init = kernel.execute(
            worker_id="runtime_orchestrator",
            target_state=RuntimeState.SCOPED,
            worker_fn=lambda env: {"payload": None, "type": "Init"},
            input_payload="init",
        )
        if init.status != WorkerStatus.SUCCESS:
            return self._halt(trace_id, kernel, "init_scoped", init)

        init2 = kernel.execute(
            worker_id="runtime_orchestrator",
            target_state=RuntimeState.CAPTURE_READY,
            worker_fn=lambda env: {"payload": None, "type": "Init"},
            input_payload="init2",
        )
        if init2.status != WorkerStatus.SUCCESS:
            return self._halt(trace_id, kernel, "init_capture_ready", init2)

        # --- Node 0: Acquisition Gateway (CAPTURE_READY -> CAPTURING) ---
        governed_packets: List[GovernedPacket] = []
        observed_artifacts: List[SemanticArtifact] = []
        for raw_req, raw_resp in raw_traffic_pairs:
            envelope_payload = self._hash_payload(raw_req + raw_resp)
            response = kernel.execute(
                worker_id="acquisition_gateway",
                target_state=RuntimeState.CAPTURING,
                worker_fn=lambda env, _req=raw_req, _resp=raw_resp: self._acquire(env, _req, _resp),
                input_payload=envelope_payload,
                artifact=None,
                provenance=[trace_id],
            )
            if response.status != WorkerStatus.SUCCESS:
                return self._halt(trace_id, kernel, "acquisition", response)
            payload = response.artifacts[0].get("payload") if response.artifacts else None
            if payload is None:
                return self._halt(trace_id, kernel, "acquisition_empty", response)
            gov = GovernedPacket(**payload)
            governed_packets.append(gov)
            # Store packet as OBSERVED artifact
            art = self.registry.derive_artifact(
                gov.packet, "NormalizedTrafficPacket", "AcquisitionGatewayNode",
                provenance=[trace_id],
                source_execution_id=response.execution_id,
                originating_runtime_state=RuntimeState.CAPTURING,
                input_hash=response.input_hash,
                output_hash=response.output_hash,
                trace_hash=response.trace_hash,
            )
            self.registry.store(art)
            observed_artifacts.append(art)

        packets: List[NormalizedTrafficPacket] = [g.packet for g in governed_packets]

        # --- Node 1: Structural Extractor (CAPTURING -> NORMALIZING) ---
        skeletons: List[ExtractedProtocolSkeleton] = []
        for packet in packets:
            response = kernel.execute(
                worker_id="structural_extractor",
                target_state=RuntimeState.NORMALIZING,
                worker_fn=lambda env, _pkt=packet: self._extract(env, _pkt),
                input_payload=packet.compute_hash(),
                artifact=None,
                provenance=[trace_id, packet.compute_hash()],
            )
            if response.status != WorkerStatus.SUCCESS:
                return self._halt(trace_id, kernel, "extraction", response)
            payload = response.artifacts[0].get("payload") if response.artifacts else None
            if payload is None:
                return self._halt(trace_id, kernel, "extraction_empty", response)
            skel = ExtractedProtocolSkeleton(**payload)
            skeletons.append(skel)

        # --- Node 2: Semantic Typer (NORMALIZING -> EXTRACTING) ---
        traces: List[SemanticIRTrace] = []
        typer_responses: List[WorkerResponse] = []
        for packet, skel in zip(packets, skeletons):
            payload = json.dumps(
                {"packet": packet.compute_hash(), "skeleton": skel.compute_hash()},
                sort_keys=True,
            )
            response = kernel.execute(
                worker_id="semantic_typer",
                target_state=RuntimeState.EXTRACTING,
                worker_fn=lambda env, _pkt=packet, _skel=skel: self._type(env, _pkt, _skel),
                input_payload=payload,
                artifact=None,
                provenance=[trace_id, packet.compute_hash()],
            )
            if response.status != WorkerStatus.SUCCESS:
                return self._halt(trace_id, kernel, "typing", response)
            payload = response.artifacts[0].get("payload") if response.artifacts else None
            if payload is None:
                return self._halt(trace_id, kernel, "typing_empty", response)
            sem = SemanticIRTrace(**payload)
            traces.append(sem)
            typer_responses.append(response)

        # Register INFERRED traces in artifact registry with full provenance
        trace_artifacts: List[SemanticArtifact] = []
        for trace, resp in zip(traces, typer_responses):
            parent_ids = [a.artifact_id for a in observed_artifacts]  # OBSERVED parents
            art = self.registry.derive_artifact(
                trace, "SemanticIRTrace", "SemanticTyperNode",
                provenance=[f"trace:{trace_id}", f"packet:{trace.endpoint_template}"],
                parent_artifact_ids=parent_ids,
                source_execution_id=resp.execution_id,
                originating_runtime_state=RuntimeState.EXTRACTING,
                input_hash=resp.input_hash,
                output_hash=resp.output_hash,
                trace_hash=resp.trace_hash,
                evidence_refs=[f"artifact:{parent_ids[0]}"] if parent_ids else [],
            )
            self.registry.store(art)
            trace_artifacts.append(art)

        # Fail-closed check: if any trace is not frozen, halt
        unfrozen = [t for t in traces if not t.is_frozen]
        if unfrozen:
            return {
                "trace_id": trace_id,
                "status": "HALTED",
                "reason": "semantic_freezing_failed",
                "unfrozen_endpoints": [t.endpoint_template for t in unfrozen],
                "governed_packets": [g.model_dump() for g in governed_packets],
                "trace_artifacts": [a.model_dump() for a in trace_artifacts],
                "kernel_report": kernel.terminal_report(),
                "state_hash": self.ledger.compute_state_hash(trace_id),
            }

        # ——— Auth Consistency Validation (EXTRACTING checkpoint) ———
        auth_report = self.auth_validator.validate(traces, packets, execution_id=trace_id)
        critical_auth = [v for v in auth_report.violations if v.severity == "CRITICAL"]
        if critical_auth:
            return self._halt(
                trace_id, kernel, "auth_consistency",
                WorkerResponse(
                    root_goal_id=trace_id,
                    worker_id="auth_consistency_validator",
                    status="VERIFICATION_MISMATCH",
                    errors=[v.rule for v in critical_auth],
                )
            )

        # Store auth report as artifact
        auth_artifact = self.registry.derive_artifact(
            auth_report, "AuthConsistencyReport", "AuthConsistencyValidator",
            provenance=[f"trace:{trace_id}", f"traces:{len(traces)}"],
            parent_artifact_ids=[a.artifact_id for a in trace_artifacts],
            source_execution_id=trace_id,
            originating_runtime_state=RuntimeState.EXTRACTING,
            input_hash=self._hash_payload(json.dumps([t.compute_hash() for t in traces], sort_keys=True)),
            evidence_refs=[f"artifact:{a.artifact_id}" for a in trace_artifacts],
        )
        self.registry.store(auth_artifact)

        # ——— State Transition FSM Extraction (EXTRACTING checkpoint) ———
        fsm, fsm_violations = self.state_validator.extract_fsm(
            traces, packets, auth_report, execution_id=trace_id
        )
        critical_fsm = [v for v in fsm_violations if v.severity == "CRITICAL"]
        if critical_fsm and auth_report.passed:
            # Only halt on CRITICAL FSM violations if verifier already passed
            return self._halt(
                trace_id, kernel, "fsm_bounds",
                WorkerResponse(
                    root_goal_id=trace_id,
                    worker_id="state_transition_validator",
                    status="VERIFICATION_MISMATCH",
                    errors=[v.rule for v in critical_fsm],
                )
            )

        fsm_artifact = self.registry.derive_artifact(
            fsm, "ProtocolStateMachine", "StateTransitionValidator",
            provenance=[f"trace:{trace_id}", f"nodes:{fsm.node_count()}", f"edges:{fsm.edge_count()}"],
            parent_artifact_ids=[auth_artifact.artifact_id] + [a.artifact_id for a in trace_artifacts],
            source_execution_id=trace_id,
            originating_runtime_state=RuntimeState.EXTRACTING,
            input_hash=self._hash_payload(json.dumps([t.compute_hash() for t in traces], sort_keys=True)),
            evidence_refs=[f"artifact:{auth_artifact.artifact_id}"],
        )
        self.registry.store(fsm_artifact)

        # ——— Semantic Quorum Resolution (EXTRACTING checkpoint) ———
        # Execute AFTER FSM extraction but BEFORE dependency graph freezing
        all_artifacts = self.registry.all_artifacts()
        quorum_report = self.semantic_quorum.execute(
            all_artifacts, execution_id=trace_id, registry=self.registry
        )
        critical_quorum = [v for v in quorum_report.violations if v.severity in ("CRITICAL", "ERROR")]
        if critical_quorum:
            return self._halt(
                trace_id, kernel, "quorum_violation",
                WorkerResponse(
                    root_goal_id=trace_id,
                    worker_id="semantic_quorum",
                    status="VERIFICATION_MISMATCH",
                    errors=[v.rule for v in critical_quorum],
                )
            )

        quorum_artifact = self.registry.derive_artifact(
            quorum_report, "SemanticQuorumReport", "SemanticQuorum",
            provenance=[f"trace:{trace_id}", f"claims:{len(quorum_report.claims)}", f"intersections:{len(quorum_report.intersections)}"],
            parent_artifact_ids=[fsm_artifact.artifact_id, auth_artifact.artifact_id] + [a.artifact_id for a in trace_artifacts],
            source_execution_id=trace_id,
            originating_runtime_state=RuntimeState.EXTRACTING,
            input_hash=self._hash_payload(json.dumps([t.compute_hash() for t in traces], sort_keys=True)),
            evidence_refs=[f"artifact:{fsm_artifact.artifact_id}"],
        )
        self.registry.store(quorum_artifact)

        # ——— Entropy Analysis (EXTRACTING checkpoint) ———
        # Execute AFTER semantic_quorum, BEFORE dependency mapping / synthesis
        # Observational ONLY. Measures stability, detects regression.
        entropy_report = self.entropy_analyzer.analyze(
            quorum_report=quorum_report,
            fsm=fsm,
            auth_report=auth_report,
            execution_id=trace_id,
            prior_snapshot=None,  # No historical window in first run
        )
        critical_entropy = [v for v in entropy_report.violations if v.severity in ("CRITICAL", "ERROR")]
        if critical_entropy:
            return self._halt(
                trace_id, kernel, "entropy_regression",
                WorkerResponse(
                    root_goal_id=trace_id,
                    worker_id="entropy_analysis",
                    status="VERIFICATION_MISMATCH",
                    errors=[v.rule for v in critical_entropy],
                )
            )

        entropy_artifact = self.registry.derive_artifact(
            entropy_report, "EntropyAnalysisReport", "EntropyAnalysis",
            provenance=[f"trace:{trace_id}", f"composite_entropy:{entropy_report.snapshot.composite_entropy}", f"convergence:{entropy_report.convergence.score}"],
            parent_artifact_ids=[quorum_artifact.artifact_id, fsm_artifact.artifact_id],
            source_execution_id=trace_id,
            originating_runtime_state=RuntimeState.EXTRACTING,
            input_hash=self._hash_payload(quorum_report.model_dump_json()),
            evidence_refs=[f"artifact:{quorum_artifact.artifact_id}"],
        )
        self.registry.store(entropy_artifact)

        # --- Node 3: Dependency Mapper (EXTRACTING -> ASSEMBLING_IR) ---
        response = kernel.execute(
            worker_id="flow_mapper",
            target_state=RuntimeState.ASSEMBLING_IR,
            worker_fn=lambda env: self._map_flow(env, traces),
            input_payload=json.dumps([t.compute_hash() for t in traces], sort_keys=True),
            artifact=None,
            provenance=[trace_id, f"traces:{len(traces)}"],
        )
        if response.status != WorkerStatus.SUCCESS:
            return self._halt(trace_id, kernel, "flow_mapping", response)
        payload = response.artifacts[0].get("payload") if response.artifacts else None
        if payload is None:
            return self._halt(trace_id, kernel, "flow_mapping_empty", response)
        graph = DependencyGraph(**payload)

        graph_artifact = self.registry.derive_artifact(
            graph, "DependencyGraph", "FlowMapperNode",
            provenance=[f"trace:{trace_id}", f"traces:{len(traces)}"],
            parent_artifact_ids=[a.artifact_id for a in trace_artifacts],
            source_execution_id=response.execution_id,
            originating_runtime_state=RuntimeState.ASSEMBLING_IR,
            input_hash=response.input_hash,
            output_hash=response.output_hash,
            trace_hash=response.trace_hash,
            evidence_refs=[f"artifact:{a.artifact_id}" for a in trace_artifacts],
        )
        self.registry.store(graph_artifact)

        # --- Node 4: Spec Synthesizer (ASSEMBLING_IR -> GENERATING_SPEC) ---
        payload = json.dumps(
            {
                "traces": [t.compute_hash() for t in traces],
                "graph": graph.session_window_id,
            },
            sort_keys=True,
        )
        response = kernel.execute(
            worker_id="spec_synthesizer",
            target_state=RuntimeState.GENERATING_SPEC,
            worker_fn=lambda env: self._synthesize(env, traces, graph),
            input_payload=payload,
            artifact=None,
            provenance=[trace_id, graph.session_window_id],
        )
        if response.status != WorkerStatus.SUCCESS:
            return self._halt(trace_id, kernel, "synthesis", response)
        payload = response.artifacts[0].get("payload") if response.artifacts else None
        if payload is None:
            return self._halt(trace_id, kernel, "synthesis_empty", response)
        spec = SynthesizedSpec(**payload)

        spec_artifact = self.registry.derive_artifact(
            spec, "SynthesizedSpec", "SpecSynthesizerNode",
            provenance=[f"trace:{trace_id}", f"graph:{graph.session_window_id}"],
            parent_artifact_ids=[graph_artifact.artifact_id] + [a.artifact_id for a in trace_artifacts],
            source_execution_id=response.execution_id,
            originating_runtime_state=RuntimeState.GENERATING_SPEC,
            input_hash=response.input_hash,
            output_hash=response.output_hash,
            trace_hash=response.trace_hash,
            evidence_refs=[f"artifact:{graph_artifact.artifact_id}"] + [f"artifact:{a.artifact_id}" for a in trace_artifacts],
        )
        self.registry.store(spec_artifact)

        # --- Node 5: Differential Verifier (GENERATING_SPEC -> COMPLETED) ---
        response = kernel.execute(
            worker_id="verifier",
            target_state=RuntimeState.COMPLETED,
            worker_fn=lambda env: self._verify(env, spec, packets),
            input_payload=self._hash_payload(spec.spec_json),
            artifact=None,
            provenance=[trace_id, spec_artifact.artifact_id],
        )
        if response.status != WorkerStatus.SUCCESS:
            return self._halt(trace_id, kernel, "verification", response)
        payload = response.artifacts[0].get("payload") if response.artifacts else None
        if payload is None:
            return self._halt(trace_id, kernel, "verification_empty", response)
        report = VerificationReport(**payload)

        # Promote artifact epistemic states based on verification
        if report.passed:
            # Bottom-up promotion: traces -> graph -> spec
            # Each promotion requires provenance closure
            for ta in trace_artifacts:
                allowed, violations = self.provenance_validator.can_promote(
                    ta, EpistemicState.VERIFIED
                )
                if not allowed:
                    return self._halt(
                        trace_id, kernel, "provenance_trace",
                        WorkerResponse(
                            root_goal_id=trace_id,
                            worker_id="provenance_validator",
                            status="VERIFICATION_MISMATCH",
                            errors=[v.rule for v in violations],
                        )
                    )
                self.registry.promote(ta, EpistemicState.VERIFIED, trust_delta=0.2)

            allowed, violations = self.provenance_validator.can_promote(
                graph_artifact, EpistemicState.VERIFIED
            )
            if not allowed:
                return self._halt(
                    trace_id, kernel, "provenance_graph",
                    WorkerResponse(
                        root_goal_id=trace_id,
                        worker_id="provenance_validator",
                        status="VERIFICATION_MISMATCH",
                        errors=[v.rule for v in violations],
                    )
                )
            self.registry.promote(graph_artifact, EpistemicState.VERIFIED, trust_delta=0.2)

            allowed, violations = self.provenance_validator.can_promote(
                spec_artifact, EpistemicState.VERIFIED
            )
            if not allowed:
                return self._halt(
                    trace_id, kernel, "provenance_spec",
                    WorkerResponse(
                        root_goal_id=trace_id,
                        worker_id="provenance_validator",
                        status="VERIFICATION_MISMATCH",
                        errors=[v.rule for v in violations],
                    )
                )
            self.registry.promote(spec_artifact, EpistemicState.VERIFIED, trust_delta=0.3)
        else:
            self.registry.promote(spec_artifact, EpistemicState.CONTESTED, trust_delta=0.0)

        # ——— Replay Consistency Check (kernel-mediated) ———
        replay_diffs: List[SemanticDiff] = []
        replay_violations: List[GovernanceViolation] = []
        if report.behavioral_deltas:
            # Synthesize replay traces from deltas for comparison
            for delta in report.behavioral_deltas:
                # Find matching original trace
                orig_trace = next(
                    (t for t in traces if t.endpoint_template == delta.path and t.method == delta.action.upper()),
                    None,
                )
                if orig_trace:
                    # Build diverged replay: same endpoint/method, but replay state
                    replay_trace = SemanticIRTrace(
                        endpoint_template=delta.path,
                        method=delta.action.upper(),
                        fields=orig_trace.fields,
                        is_frozen=orig_trace.is_frozen,
                        epistemic_state=EpistemicState.CONTESTED if delta.contradiction_detected else orig_trace.epistemic_state,
                        provenance=[f"replay:{trace_id}"],
                        generated_by="ReplayValidator",
                    )
                    diff, r_violations = self.replay_validator.compare(
                        orig_trace, replay_trace, execution_id=trace_id
                    )
                    replay_diffs.append(diff)
                    replay_violations.extend(r_violations)
        else:
            # Sanity check: compare first trace to itself (should be STRICT_EQUIVALENT)
            if traces:
                diff, r_violations = self.replay_validator.compare(
                    traces[0], traces[0], execution_id=trace_id
                )
                replay_diffs.append(diff)
                replay_violations.extend(r_violations)

        # If replay violations are CRITICAL, do NOT promote to VERIFIED
        critical_replay = [v for v in replay_violations if v.severity == "CRITICAL"]
        if critical_replay and report.passed:
            return self._halt(
                trace_id, kernel, "replay_critical",
                WorkerResponse(
                    root_goal_id=trace_id,
                    worker_id="replay_validator",
                    status="VERIFICATION_MISMATCH",
                    errors=[v.rule for v in critical_replay],
                )
            )

        # ——— Final ledger entries ———
        self._log_trace(
            trace_id, "PipelineDriver",
            self._hash_payload(json.dumps([p.compute_hash() for p in packets])),
            json.dumps({"status": "SUCCESS" if report.passed else "CONTESTED"}),
            report.passed,
        )

        return {
            "trace_id": trace_id,
            "status": "SUCCESS" if report.passed else "VERIFICATION_FAILURE",
            "epistemic_state": EpistemicState.VERIFIED if report.passed else EpistemicState.CONTESTED,
            "governed_packets": [g.model_dump() for g in governed_packets],
            "skeletons": [s.model_dump() for s in skeletons],
            "traces": [t.model_dump() for t in traces],
            "graph": graph.model_dump(),
            "spec": spec.model_dump(),
            "verification": report.model_dump(),
            "auth_consistency": auth_report.model_dump(),
            "quorum": quorum_report.model_dump(),
            "entropy": entropy_report.model_dump(),
            "replay_diffs": [d.model_dump() for d in replay_diffs],
            "replay_violations": [v.model_dump() for v in replay_violations],
            "replay_equivalence": replay_diffs[0].replay_equivalence if replay_diffs else EquivalenceClass.CONTESTED,
            "state_hash": self.ledger.compute_state_hash(trace_id),
            "artifact_registry_size": len(self.registry.all_artifacts()),
            "kernel_report": kernel.terminal_report(),
        }

    # --- Worker wrappers (pure transforms, no state, no orchestration) ---

    def _acquire(self, envelope, raw_req: str, raw_resp: str) -> Dict[str, Any]:
        gov = self.acquirer.from_raw_http_pair(
            raw_req, raw_resp, url_override=self.base_url
        )
        return {"payload": gov.model_dump(), "type": "GovernedPacket"}

    def _extract(self, envelope, packet: NormalizedTrafficPacket) -> Dict[str, Any]:
        skel = self.extractor.extract(packet)
        return {"payload": skel.model_dump(), "type": "ExtractedProtocolSkeleton"}

    def _type(self, envelope, packet: NormalizedTrafficPacket, skel: ExtractedProtocolSkeleton) -> Dict[str, Any]:
        sem = self.typer.analyze(packet, skel)
        return {"payload": sem.model_dump(), "type": "SemanticIRTrace"}

    def _map_flow(self, envelope, traces: List[SemanticIRTrace]) -> Dict[str, Any]:
        graph = self.mapper.map_flow(traces)
        return {"payload": graph.model_dump(), "type": "DependencyGraph"}

    def _synthesize(self, envelope, traces: List[SemanticIRTrace], graph: DependencyGraph) -> Dict[str, Any]:
        spec = self.synthesizer.synthesize(traces, graph)
        return {"payload": spec.model_dump(), "type": "SynthesizedSpec"}

    def _verify(self, envelope, spec: SynthesizedSpec, packets: List[NormalizedTrafficPacket]) -> Dict[str, Any]:
        import asyncio
        report = asyncio.run(self.verifier.verify(spec, packets))
        return {"payload": report.model_dump(), "type": "VerificationReport"}

    # --- Utility ---

    def _halt(
        self,
        trace_id: str,
        kernel: GovernanceKernel,
        stage: str,
        response: WorkerResponse,
    ) -> Dict[str, Any]:
        """Emit a governed halt response."""
        self._log_trace(
            trace_id, "PipelineDriver",
            response.input_hash or "",
            json.dumps({
                "status": "HALTED",
                "stage": stage,
                "worker_status": response.status,
                "errors": response.errors,
            }),
            False,
            error="; ".join(response.errors) if response.errors else "Governance halt",
        )
        return {
            "trace_id": trace_id,
            "status": "HALTED",
            "reason": f"governance_{stage}",
            "worker_status": response.status,
            "errors": response.errors,
            "kernel_report": kernel.terminal_report(),
            "state_hash": self.ledger.compute_state_hash(trace_id),
        }

    def _log_trace(
        self,
        trace_id: str,
        node_name: str,
        input_hash: str,
        raw_output: str,
        is_valid: bool,
        error: Optional[str] = None,
    ) -> None:
        trace = ExecutionTrace(
            trace_id=trace_id,
            node_name=node_name,
            input_payload_hash=input_hash,
            llm_seed=self.config.verification_replay_seed,
            llm_temperature=0.0,
            raw_output=raw_output,
            is_valid_type=is_valid,
            error_message=error,
        )
        self.ledger.append(trace)

    @staticmethod
    def _hash_payload(payload: str) -> str:
        return hashlib.sha256(payload.encode()).hexdigest()
