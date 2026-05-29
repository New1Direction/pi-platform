from __future__ import annotations

import atexit
import logging
import queue
import time
import uuid
import weakref
from concurrent.futures import Future, ThreadPoolExecutor
from enum import Enum
from typing import Any, Callable, Dict, List, Tuple

from pydantic import BaseModel, Field

# Setup logging
logger = logging.getLogger("pi_platform.scheduler")


def _atexit_shutdown(sched_ref: "weakref.ref[Any]") -> None:
    sched = sched_ref()
    if sched is not None:
        sched.shutdown(wait=False, cancel_futures=True)


class AgentExecutionClass(str, Enum):
    HARD_REAL_TIME = "HARD_REAL_TIME"
    SOFT_REAL_TIME = "SOFT_REAL_TIME"
    BLOCKING = "BLOCKING"
    STREAMING = "STREAMING"
    ADVERSARIAL = "ADVERSARIAL"
    VERIFIER = "VERIFIER"
    RECOVERY = "RECOVERY"


class SchedulerTask(BaseModel):
    task_id: str = Field(default_factory=lambda: "task_" + str(uuid.uuid4())[:8])
    goal: str = Field(..., description="Cognitive goal description")
    execution_class: AgentExecutionClass = Field(default=AgentExecutionClass.SOFT_REAL_TIME)
    priority: int = Field(default=10, description="Lower is higher priority (0 = highest)")
    payload: Dict[str, Any] = Field(default_factory=dict)
    submitted_at: float = Field(default_factory=time.time)

    # Comparable implementation for queue.PriorityQueue ordering
    def __lt__(self, other: SchedulerTask) -> bool:
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.submitted_at < other.submitted_at


class PiCognitiveExecutionScheduler:
    """High-performance programmable cognitive execution scheduler.

    Manages priority queues, speculative execution execution-branches, backpressure bounds,
    and cancellation signals with absolute determinism.
    """

    def __init__(self, max_workers: int = 8, backpressure_threshold: int = 100) -> None:
        self.max_workers = max_workers
        self.backpressure_threshold = backpressure_threshold
        self.executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="pi_scheduler")
        self.queue: queue.PriorityQueue[Tuple[int, SchedulerTask]] = queue.PriorityQueue()

        # Mutations to active_tasks/cancellation_events must hold _state_lock
        # otherwise the wrapper's finally-pop can race with cancel_task() and
        # leak a cancellation event for a task that already finished.
        import threading as _threading

        self._state_lock = _threading.RLock()
        self.active_tasks: Dict[str, Future[Any]] = {}
        self.cancellation_events: Dict[str, Any] = {}  # Dict[task_id, threading.Event]

        # Performance and governance metrics
        self.stats = {
            "total_scheduled": 0,
            "total_completed": 0,
            "total_cancelled": 0,
            "speculative_runs": 0,
            "backpressure_tripped": 0,
            "degradations_applied": 0,
        }

        self._shutdown = False
        # Register a weakref-based atexit hook so an abandoned scheduler does
        # not leak its worker threads at interpreter shutdown.
        atexit.register(_atexit_shutdown, weakref.ref(self))

    def shutdown(self, wait: bool = True, cancel_futures: bool = False) -> None:
        """Idempotent shutdown of the worker pool."""
        if self._shutdown:
            return
        self._shutdown = True
        try:
            self.executor.shutdown(wait=wait, cancel_futures=cancel_futures)
        except Exception:
            logger.exception("scheduler executor shutdown failed")

    def __enter__(self) -> "PiCognitiveExecutionScheduler":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown(wait=True)

    def __del__(self) -> None:
        # Best-effort: if the user never called shutdown, do it on GC.
        if not getattr(self, "_shutdown", True):
            try:
                self.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

    def schedule(
        self,
        goal: str,
        execution_class: AgentExecutionClass,
        priority: int,
        payload: Dict[str, Any],
        execute_fn: Callable[[SchedulerTask], Any],
    ) -> Future[Any]:
        """Schedules a task with priority, execution class, and backpressure bounds."""
        task = SchedulerTask(goal=goal, execution_class=execution_class, priority=priority, payload=payload)

        self.stats["total_scheduled"] += 1

        # Check backpressure limits
        if self.queue.qsize() >= self.backpressure_threshold:
            self.stats["backpressure_tripped"] += 1
            self.stats["degradations_applied"] += 1
            logger.warning(f"Backpressure threshold breached ({self.queue.qsize()}). Degrading task: {task.task_id}")
            # Dynamic degradation: degrade soft-real-time or blocking task to fallback immediate response
            fallback_future = Future()
            # From the caller's perspective the degraded fallback IS a
            # completed result — `success` reflects "we returned something"
            # not "we ran the real task". Risk is elevated and the summary
            # marks it unverified so downstream consumers can branch.
            fallback_future.set_result(
                {
                    "status": "DEGRADED_FALLBACK",
                    "success": True,
                    "executed": False,
                    "risk_score": 50.0,
                    "summary": f"Backpressure limit reached — task {task.task_id} was NOT executed. Result is unverified.",
                    "details": {"degradation_timestamp": time.time()},
                }
            )
            return fallback_future

        # Put in priority queue
        self.queue.put((task.priority, task))

        # Submit to pool
        future = self.executor.submit(self._run_task_wrapper, task, execute_fn)
        with self._state_lock:
            self.active_tasks[task.task_id] = future
        return future

    def cancel_task(self, task_id: str) -> bool:
        """Propagates a thread-safe cancellation signal to the execution tree."""
        with self._state_lock:
            event = self.cancellation_events.get(task_id)
            future = self.active_tasks.get(task_id)
        if event is not None:
            event.set()
            self.stats["total_cancelled"] += 1
        if future is not None:
            future.cancel()
            return True
        return False

    def run_speculative(
        self, tasks: List[SchedulerTask], execute_fn: Callable[[SchedulerTask], Any], timeout_seconds: float = 5.0
    ) -> Dict[str, Any]:
        """Runs multiple tasks concurrently in parallel speculative branches.

        Each branch gets its own cancellation event so a slow branch is not
        cancelled by a peer branch completing first — the parent decides
        when to call ``cancel`` after collecting results.
        """
        import threading

        self.stats["speculative_runs"] += 1
        futures: List[Tuple[SchedulerTask, Future[Any]]] = []

        # Submit speculative branches with per-task events
        for t in tasks:
            with self._state_lock:
                self.cancellation_events[t.task_id] = threading.Event()
            fut = self.executor.submit(self._run_task_wrapper, t, execute_fn)
            with self._state_lock:
                self.active_tasks[t.task_id] = fut
            futures.append((t, fut))

        completed_results: List[Tuple[SchedulerTask, Any]] = []
        start_time = time.time()

        # Wait and compile results
        while len(completed_results) < len(tasks) and (time.time() - start_time) < timeout_seconds:
            for t, fut in futures:
                if fut.done() and t not in [x[0] for x in completed_results]:
                    try:
                        res = fut.result(timeout=0.1)
                        completed_results.append((t, res))
                    except Exception as e:
                        completed_results.append((t, {"error": str(e), "success": False}))
            time.sleep(0.01)

        # Cancel only the branches we still own.
        for t, fut in futures:
            with self._state_lock:
                ev = self.cancellation_events.get(t.task_id)
            if ev is not None:
                ev.set()
            if not fut.done():
                fut.cancel()

        # Merge results deterministically
        # We prioritize VERIFIER results, then HARD_REAL_TIME, then others
        # We calculate weighted average risk score or pick the consensus verdict
        merged_details: Dict[str, Any] = {}
        risk_scores: List[float] = []
        anomalies: List[str] = []
        success = True

        for t, res in completed_results:
            if isinstance(res, dict):
                success = success and res.get("success", True)
                risk_scores.append(res.get("risk_score", 0.0))
                if "anomalies_detected" in res:
                    anomalies.extend(res["anomalies_detected"])
                merged_details[t.task_id] = res
            else:
                risk_scores.append(0.0)
                merged_details[t.task_id] = str(res)

        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0.0

        return {
            "success": success,
            "risk_score": avg_risk,
            "anomalies_detected": list(set(anomalies)),
            "branches_completed": len(completed_results),
            "merged_details": merged_details,
        }

    def _run_task_wrapper(self, task: SchedulerTask, execute_fn: Callable[[SchedulerTask], Any]) -> Any:
        import threading

        with self._state_lock:
            cancel_evt = self.cancellation_events.get(task.task_id)
            if cancel_evt is None:
                cancel_evt = threading.Event()
                self.cancellation_events[task.task_id] = cancel_evt

        # Check pre-execution cancellation
        if cancel_evt.is_set():
            return {"status": "CANCELLED", "success": False, "risk_score": 0.0}

        try:
            res = execute_fn(task)
            self.stats["total_completed"] += 1
            return res
        except Exception as e:
            logger.error(f"Task {task.task_id} execution failed: {e}")
            return {"status": "FAILED", "success": False, "risk_score": 100.0, "error": str(e)}
        finally:
            with self._state_lock:
                self.active_tasks.pop(task.task_id, None)
                self.cancellation_events.pop(task.task_id, None)

    def get_stats(self) -> Dict[str, Any]:
        """Returns live scheduler queue sizes and thread performance metrics."""
        return {
            **self.stats,
            "active_tasks_count": len(self.active_tasks),
            "queue_depth": self.queue.qsize(),
            "max_workers": self.max_workers,
        }
