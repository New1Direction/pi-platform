"""Governance Kernel.

The mathematically paranoid gatekeeper.

The runtime is the intelligence. Workers are constrained semantic transforms.
The runtime enforces transitions, validates schemas, manages retries,
constrains branching, controls tool access, limits recursion depth,
owns replay logs, enforces bounded execution.

Nothing is trusted. Everything is validated.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from pi_agent_chain.governance.entropy_monitor import EntropyMonitor
from pi_agent_chain.governance.objective_tracker import ObjectiveTracker
from pi_agent_chain.governance.schema_gate import SchemaGate
from pi_agent_chain.governance.transition_gate import TransitionGate
from pi_agent_chain.models import (
    EpistemicState,
    ExecutionTrace,
    GovernanceConfig,
    GovernanceViolation,
    RuntimeState,
    WorkerEnvelope,
    WorkerResponse,
    WorkerStatus,
)


class GovernanceKernel:
    """Orchestrates ALL gates and enforcement layers.

    Workers receive a WorkerEnvelope and return a WorkerResponse.
    The kernel validates every boundary crossing.
    The ONLY legal execution path between nodes.
    """

    def __init__(
        self,
        root_goal_id: str,
        objective_scope: Dict[str, Any],
        config: Optional[GovernanceConfig] = None,
    ) -> None:
        self.root_goal_id = root_goal_id
        self.config = config or GovernanceConfig()
        self.transition_gate = TransitionGate()
        self.schema_gate = SchemaGate()
        self.objective_tracker = ObjectiveTracker(root_goal_id, objective_scope)
        self.entropy_monitor = EntropyMonitor()
        self._violations: List[GovernanceViolation] = []
        self._current_state: str = RuntimeState.REGISTERED
        self._depth: int = 0
        self._branch_count: int = 0
        self._execution_counter: int = 0

    @property
    def current_state(self) -> str:
        return self._current_state

    @property
    def violations(self) -> List[GovernanceViolation]:
        return list(self._violations)

    def is_halted(self) -> bool:
        """Check if any critical violation has forced a halt."""
        return any(v.severity == "CRITICAL" for v in self._violations)

    def should_retry(self) -> bool:
        """Check if the current state allows retry."""
        return self._current_state == RuntimeState.RETRY_PENDING

    def _generate_execution_id(self) -> str:
        self._execution_counter += 1
        return f"exec_{self.root_goal_id}_{self._execution_counter:04d}"

    def _compute_hash(self, payload: str) -> str:
        return hashlib.sha256(payload.encode()).hexdigest()

    def execute(
        self,
        worker_id: str,
        target_state: str,
        worker_fn: Callable[[WorkerEnvelope], Any],
        input_payload: str = "",
        artifact: Any = None,
        provenance: Optional[List[str]] = None,
    ) -> WorkerResponse:
        """The ONLY legal execution path.

        1. Construct WorkerEnvelope
        2. Validate transition legality
        3. Execute worker
        4. Validate schema
        5. Validate objective integrity
        6. Evaluate entropy delta
        7. Record violations
        8. Commit RuntimeState transition
        9. Return immutable WorkerResponse
        """
        exec_id = self._generate_execution_id()

        envelope = WorkerEnvelope(
            root_goal_id=self.root_goal_id,
            worker_id=worker_id,
            state_id=self._current_state,
            input_ref=exec_id,
            input_payload=input_payload,
            execution_budget={
                "max_tokens": self.config.bounded_context_window,
                "max_seconds": 30,
                "max_retries": self.config.max_inference_iterations,
            },
            objective_scope=self.objective_tracker.objective_scope,
            allowed_transitions=self._allowed_transitions_from(self._current_state),
            allowed_workers=[worker_id],  # Worker may NOT self-select targets
            depth=self._depth,
            branch_count=self._branch_count,
            provenance=provenance or [],
            execution_id=exec_id,
            parent_execution_id=exec_id if self._execution_counter == 1 else f"exec_{self.root_goal_id}_{self._execution_counter - 1:04d}",
            trace_hash="",
            prompt_hash=self._compute_hash(input_payload),
            input_hash=self._compute_hash(input_payload),
            model_identifier="semantic-transformer-v1",
            schema_version="1.0.0",
        )

        # --- STEP 1: Validate transition legality BEFORE execution ---
        synthetic_response = WorkerResponse(
            root_goal_id=self.root_goal_id,
            worker_id=worker_id,
            status=WorkerStatus.SUCCESS,
            execution_id=exec_id,
        )
        violation = self.transition_gate.validate(
            self._current_state,
            target_state,
            synthetic_response,
            depth=self._depth,
            branch_count=self._branch_count,
        )
        if violation:
            self._violations.append(violation)
            return WorkerResponse(
                root_goal_id=self.root_goal_id,
                worker_id=worker_id,
                status=WorkerStatus.BRANCH_OVERFLOW,
                errors=[f"Transition blocked: {violation.rule}"],
                execution_id=exec_id,
            )

        # --- STEP 2: Execute worker ---
        start_ms = int(time.time() * 1000)
        try:
            worker_output = worker_fn(envelope)
            raw_output_json = json.dumps(worker_output, sort_keys=True, default=str)
            output_hash = self._compute_hash(raw_output_json)
            exec_time = int(time.time() * 1000) - start_ms
        except Exception as exc:
            exec_time = int(time.time() * 1000) - start_ms
            error_response = WorkerResponse(
                root_goal_id=self.root_goal_id,
                worker_id=worker_id,
                status=WorkerStatus.FAILURE,
                errors=[str(exc)],
                execution_id=exec_id,
                execution_time_ms=exec_time,
            )
            self._violations.append(
                GovernanceViolation(
                    violation_id=str(uuid.uuid4())[:16],
                    rule="WORKER_EXECUTION_FAILURE",
                    worker_id=worker_id,
                    root_goal_id=self.root_goal_id,
                    severity="ERROR",
                    context={"error": str(exc)},
                    action_taken="HALT",
                )
            )
            return error_response

        # --- STEP 3: Build WorkerResponse ---
        try:
            payload_dict = json.loads(raw_output_json)
        except json.JSONDecodeError:
            payload_dict = {"raw": raw_output_json}
        response = WorkerResponse(
            root_goal_id=self.root_goal_id,
            worker_id=worker_id,
            status=WorkerStatus.SUCCESS,
            execution_id=exec_id,
            artifacts=[payload_dict],
            input_hash=envelope.input_hash,
            output_hash=output_hash,
            execution_time_ms=exec_time,
        )

        # --- STEP 4: Schema validation ---
        schema_violation = self.schema_gate.validate(worker_id, payload_dict, response)
        if schema_violation:
            self._violations.append(schema_violation)
            # FAIL-CLOSED: Invalid output immediately halts
            return WorkerResponse(
                root_goal_id=self.root_goal_id,
                worker_id=worker_id,
                status=WorkerStatus.INVALID_OUTPUT,
                errors=[f"Schema violation: {schema_violation.rule}"],
                execution_id=exec_id,
                input_hash=envelope.input_hash,
                output_hash=output_hash,
                execution_time_ms=exec_time,
            )

        # --- STEP 5: Objective integrity ---
        objective_violation = self.objective_tracker.validate_worker_response(response)
        if objective_violation:
            self._violations.append(objective_violation)
            # FAIL-CLOSED: Objective drift immediately halts
            return WorkerResponse(
                root_goal_id=self.root_goal_id,
                worker_id=worker_id,
                status=WorkerStatus.OBJECTIVE_DRIFT_DETECTED,
                errors=[f"Objective violation: {objective_violation.rule}"],
                execution_id=exec_id,
                input_hash=envelope.input_hash,
                output_hash=output_hash,
                execution_time_ms=exec_time,
            )

        # --- STEP 6: Entropy evaluation ---
        if artifact is not None:
            snapshot = self.entropy_monitor.capture(self._current_state, artifact)
            entropy_warning = self.entropy_monitor.check_monotonic_decrease()
            if entropy_warning and self._current_state in {
                RuntimeState.ASSEMBLING_IR,
                RuntimeState.GENERATING_SPEC,
                RuntimeState.COMPLETED,
            }:
                entropy_violation = GovernanceViolation(
                    violation_id=str(uuid.uuid4())[:16],
                    rule="ENTROPY_INCREASE",
                    worker_id=worker_id,
                    root_goal_id=self.root_goal_id,
                    severity="ERROR",
                    context={"warning": entropy_warning, "snapshot": snapshot.model_dump()},
                    action_taken="HALT",
                )
                self._violations.append(entropy_violation)
                return WorkerResponse(
                    root_goal_id=self.root_goal_id,
                    worker_id=worker_id,
                    status=WorkerStatus.VERIFICATION_MISMATCH,
                    errors=[f"Entropy violation: {entropy_warning}"],
                    execution_id=exec_id,
                    input_hash=envelope.input_hash,
                    output_hash=output_hash,
                    execution_time_ms=exec_time,
                )

        # --- STEP 7: Commit state transition ---
        self._current_state = target_state
        # Depth and branch counters only apply to recursive/retry scenarios.
        # Linear pipeline progression does not increment depth.
        response.next_state = target_state

        return response

    def _allowed_transitions_from(self, state_id: str) -> List[str]:
        """List allowed next states from the current state."""
        return [
            rule.to_state
            for rule in self.transition_gate.rules
            if rule.from_state == state_id
        ]

    def terminal_report(self) -> Dict[str, Any]:
        """Emit a final governance summary."""
        return {
            "root_goal_id": self.root_goal_id,
            "final_state": self._current_state,
            "depth_reached": self._depth,
            "violations": len(self._violations),
            "critical_violations": sum(1 for v in self._violations if v.severity == "CRITICAL"),
            "entropy_history": [s.model_dump() for s in self.entropy_monitor.history],
            "halted": self.is_halted(),
        }
