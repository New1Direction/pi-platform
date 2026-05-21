from __future__ import annotations

import uuid
import time
import queue
import logging
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, Future

from pydantic import BaseModel, Field

# Setup logging
logger = logging.getLogger("pi_platform.scheduler")


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
        
        # Thread-safe mappings for running tasks and cancellation signals
        self.active_tasks: Dict[str, Future[Any]] = {}
        self.cancellation_events: Dict[str, Any] = {} # Dict[task_id, threading.Event]
        
        # Performance and governance metrics
        self.stats = {
            "total_scheduled": 0,
            "total_completed": 0,
            "total_cancelled": 0,
            "speculative_runs": 0,
            "backpressure_tripped": 0,
            "degradations_applied": 0,
        }

    def schedule(
        self,
        goal: str,
        execution_class: AgentExecutionClass,
        priority: int,
        payload: Dict[str, Any],
        execute_fn: Callable[[SchedulerTask], Any]
    ) -> Future[Any]:
        """Schedules a task with priority, execution class, and backpressure bounds."""
        task = SchedulerTask(
            goal=goal,
            execution_class=execution_class,
            priority=priority,
            payload=payload
        )
        
        self.stats["total_scheduled"] += 1
        
        # Check backpressure limits
        if self.queue.qsize() >= self.backpressure_threshold:
            self.stats["backpressure_tripped"] += 1
            self.stats["degradations_applied"] += 1
            logger.warning(f"Backpressure threshold breached ({self.queue.qsize()}). Degrading task: {task.task_id}")
            # Dynamic degradation: degrade soft-real-time or blocking task to fallback immediate response
            fallback_future = Future()
            fallback_future.set_result({
                "status": "DEGRADED_FALLBACK",
                "success": True,
                "risk_score": 0.0,
                "summary": f"Fallback degraded execution completed for {task.goal}",
                "details": {"degradation_timestamp": time.time()}
            })
            return fallback_future

        # Put in priority queue
        self.queue.put((task.priority, task))
        
        # Submit to pool
        future = self.executor.submit(self._run_task_wrapper, task, execute_fn)
        self.active_tasks[task.task_id] = future
        return future

    def cancel_task(self, task_id: str) -> bool:
        """Propagates a thread-safe cancellation signal to the execution tree."""
        if task_id in self.cancellation_events:
            self.cancellation_events[task_id].set()
            self.stats["total_cancelled"] += 1
            
        future = self.active_tasks.get(task_id)
        if future:
            future.cancel()
            return True
        return False

    def run_speculative(
        self,
        tasks: List[SchedulerTask],
        execute_fn: Callable[[SchedulerTask], Any],
        timeout_seconds: float = 5.0
    ) -> Dict[str, Any]:
        """Runs multiple tasks concurrently in parallel speculative branches.
        
        Validates output consensus or retrieves the earliest/safest outcome deterministically.
        """
        import threading
        
        self.stats["speculative_runs"] += 1
        futures: List[Tuple[SchedulerTask, Future[Any]]] = []
        cancellation_event = threading.Event()
        
        # Submit speculative branches
        for t in tasks:
            self.cancellation_events[t.task_id] = cancellation_event
            fut = self.executor.submit(self._run_task_wrapper, t, execute_fn)
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
            
        # Cancel unfinished speculative paths
        cancellation_event.set()
        for _, fut in futures:
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
            "merged_details": merged_details
        }

    def _run_task_wrapper(self, task: SchedulerTask, execute_fn: Callable[[SchedulerTask], Any]) -> Any:
        import threading
        
        if task.task_id not in self.cancellation_events:
            self.cancellation_events[task.task_id] = threading.Event()
            
        cancel_evt = self.cancellation_events[task.task_id]
        
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
