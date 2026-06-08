"""
recovery.py — structured retry semantics with circuit breaker.

- RetryPolicy: per-step backoff config.
- CircuitBreaker: process-wide breaker keyed by step name; opens after N
  consecutive failures to prevent thundering-herd retries against a sick
  downstream. Half-opens after a cool-off and closes on first success.
- ChainRecoveryPolicy: wraps a step_fn with retries + breaker.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from pydantic import BaseModel

# OS-backed CSPRNG. random.uniform is fine for jitter on its own, but if an
# observer can time retry attempts they can fingerprint the seeded PRNG and
# predict subsequent jitter values — using SystemRandom closes that channel.
_jitter_rng = secrets.SystemRandom()


class RetryPolicy(BaseModel):
    max_retries: int = 3
    backoff_base_ms: float = 100.0
    backoff_multiplier: float = 2.0
    max_backoff_ms: float = 5000.0
    jitter_ms: float = 50.0
    retryable_risk_threshold: float = 90.0
    retry_on_exception: bool = True

    def compute_delay_ms(self, attempt: int) -> float:
        base = self.backoff_base_ms * (self.backoff_multiplier ** max(0, attempt))
        capped = min(base, self.max_backoff_ms)
        jitter = _jitter_rng.uniform(-self.jitter_ms, self.jitter_ms)
        return max(0.0, capped + jitter)


class StepRecoveryResult(BaseModel):
    step_name: str
    success: bool
    attempts: int
    total_delay_ms: float = 0.0
    last_output: Optional[Any] = None
    last_error: Optional[str] = None
    breaker_tripped: bool = False


@dataclass
class _BreakerState:
    consecutive_failures: int = 0
    opened_at: float = 0.0
    state: str = "closed"  # closed | open | half_open


class CircuitBreaker:
    """
    Per-step circuit breaker.

    closed   → all calls allowed; consecutive failures increment counter.
    open     → calls short-circuit immediately for `cool_off_seconds`.
    half_open → next call probes downstream; success closes, failure re-opens.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        cool_off_seconds: float = 30.0,
    ):
        self.failure_threshold = max(1, int(failure_threshold))
        self.cool_off_seconds = max(0.0, float(cool_off_seconds))
        self._states: Dict[str, _BreakerState] = {}
        self._lock = threading.RLock()

    def _get(self, name: str) -> _BreakerState:
        with self._lock:
            return self._states.setdefault(name, _BreakerState())

    def allow(self, step_name: str) -> bool:
        s = self._get(step_name)
        with self._lock:
            if s.state == "closed":
                return True
            if s.state == "open":
                if time.time() - s.opened_at >= self.cool_off_seconds:
                    s.state = "half_open"
                    return True
                return False
            return True

    def record_success(self, step_name: str) -> None:
        s = self._get(step_name)
        with self._lock:
            s.consecutive_failures = 0
            s.opened_at = 0.0
            s.state = "closed"

    def record_failure(self, step_name: str) -> bool:
        """Increment failure counter. Returns True if breaker is now open."""
        s = self._get(step_name)
        with self._lock:
            s.consecutive_failures += 1
            if s.state == "half_open":
                s.state = "open"
                s.opened_at = time.time()
                return True
            if s.consecutive_failures >= self.failure_threshold:
                s.state = "open"
                s.opened_at = time.time()
                return True
            return False

    def status(self, step_name: str) -> Dict[str, Any]:
        s = self._get(step_name)
        with self._lock:
            return {
                "step_name": step_name,
                "state": s.state,
                "consecutive_failures": s.consecutive_failures,
                "opened_at": s.opened_at,
                "seconds_until_half_open": max(0.0, self.cool_off_seconds - (time.time() - s.opened_at))
                if s.state == "open"
                else 0.0,
            }


class ChainRecoveryPolicy:
    """
    Wraps a step function with retry + circuit-breaker semantics.

    step_fn signature:  () -> dict  with keys {success: bool, risk_score: float, ...}
    """

    def __init__(
        self,
        policy: Optional[RetryPolicy] = None,
        breaker: Optional[CircuitBreaker] = None,
    ):
        self.policy = policy or RetryPolicy()
        self.breaker = breaker or CircuitBreaker()

    def execute(
        self,
        step_name: str,
        step_fn: Callable[[], Dict[str, Any]],
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> StepRecoveryResult:
        if not self.breaker.allow(step_name):
            status = self.breaker.status(step_name)
            return StepRecoveryResult(
                step_name=step_name,
                success=False,
                attempts=0,
                last_error=f"circuit_breaker_open: {status}",
                breaker_tripped=True,
            )

        total_delay = 0.0
        last_output: Optional[Dict[str, Any]] = None
        last_error: Optional[str] = None
        attempts = 0
        max_attempts = max(1, self.policy.max_retries + 1)

        for attempt in range(max_attempts):
            attempts += 1
            try:
                last_output = step_fn() or {}
                ok = bool(last_output.get("success"))
                risk = float(last_output.get("risk_score", 0.0))
                if ok:
                    self.breaker.record_success(step_name)
                    return StepRecoveryResult(
                        step_name=step_name,
                        success=True,
                        attempts=attempts,
                        total_delay_ms=total_delay,
                        last_output=last_output,
                    )
                if risk >= self.policy.retryable_risk_threshold:
                    last_error = f"risk_score {risk} >= threshold; not retrying"
                    break
            except Exception as e:
                last_error = f"{type(e).__name__}: {e}"
                last_output = None
                if not self.policy.retry_on_exception:
                    break

            if attempt < max_attempts - 1:
                delay_ms = self.policy.compute_delay_ms(attempt)
                total_delay += delay_ms
                sleep_fn(delay_ms / 1000.0)

        tripped = self.breaker.record_failure(step_name)
        return StepRecoveryResult(
            step_name=step_name,
            success=False,
            attempts=attempts,
            total_delay_ms=total_delay,
            last_output=last_output,
            last_error=last_error or "step failed",
            breaker_tripped=tripped,
        )
