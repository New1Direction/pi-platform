"""Deterministic Telemetry & Observability.

Custom lightweight telemetry system — no OpenTelemetry dependency required.
Produces Prometheus-compatible metrics, structured logs, and trace spans
all tied to deterministic correlation IDs.

All metrics are deterministic counters/gauges/histograms. No random sampling.
All log lines include correlation_id for end-to-end request tracing.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple

# ──────────────────────────────
#  Structured Logging
# ──────────────────────────────


class StructuredLogger:
    """Deterministic structured logger with correlation tracking.

    Every log line is JSON. correlation_id is always present.
    No log levels that vary by environment — all events logged deterministically.
    """

    def __init__(self, component: str) -> None:
        self.component = component
        self._correlation: ContextVar[str] = ContextVar("correlation_id", default="")

    def set_correlation(self, cid: str) -> None:
        self._correlation.set(cid)

    def log(self, event: str, level: str, **fields: Any) -> Dict[str, Any]:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "component": self.component,
            "correlation_id": self._correlation.get() or "",
            "level": level,
            "event": event,
            **fields,
        }
        # Deterministic JSON output
        print(json.dumps(entry, sort_keys=True, default=str, separators=(",", ":")))
        return entry

    def info(self, event: str, **fields: Any) -> Dict[str, Any]:
        return self.log(event, "INFO", **fields)

    def warn(self, event: str, **fields: Any) -> Dict[str, Any]:
        return self.log(event, "WARN", **fields)

    def error(self, event: str, **fields: Any) -> Dict[str, Any]:
        return self.log(event, "ERROR", **fields)

    def audit(self, event: str, **fields: Any) -> Dict[str, Any]:
        return self.log(event, "AUDIT", **fields)


# ──────────────────────────────
#  Metrics Registry (Prometheus-compatible)
# ──────────────────────────────


@dataclass(frozen=True)
class MetricKey:
    name: str
    labels: Tuple[Tuple[str, str], ...]
    type: str  # counter | gauge | histogram


class MetricsRegistry:
    """Deterministic metrics registry — thread-safe, no random sampling.

    Produces text in Prometheus exposition format.
    """

    def __init__(self) -> None:
        self._counters: Dict[str, Dict[Tuple, int]] = defaultdict(lambda: defaultdict(int))
        self._gauges: Dict[str, Dict[Tuple, float]] = defaultdict(lambda: defaultdict(float))
        self._histograms: Dict[str, Dict[Tuple, List[float]]] = defaultdict(lambda: defaultdict(list))
        self._label_names: Dict[str, List[str]] = {}
        self._lock = threading.Lock()

    def counter(self, name: str, label_names: List[str], labels: Dict[str, str], value: int = 1) -> None:
        with self._lock:
            self._label_names[name] = label_names
            key = tuple(labels.get(l, "") for l in label_names)
            self._counters[name][key] += value

    def gauge(self, name: str, label_names: List[str], labels: Dict[str, str], value: float) -> None:
        with self._lock:
            self._label_names[name] = label_names
            key = tuple(labels.get(l, "") for l in label_names)
            self._gauges[name][key] = value

    def histogram(self, name: str, label_names: List[str], labels: Dict[str, str], value: float) -> None:
        with self._lock:
            self._label_names[name] = label_names
            key = tuple(labels.get(l, "") for l in label_names)
            self._histograms[name][key].append(value)

    def prometheus_format(self) -> str:
        """Export all metrics in Prometheus text exposition format."""
        lines: List[str] = []

        for name, data in self._counters.items():
            lines.append(f"# TYPE {name} counter")
            for key, val in sorted(data.items()):
                labels = self._format_labels(name, key)
                lines.append(f"{name}{labels} {val}")

        for name, data in self._gauges.items():
            lines.append(f"# TYPE {name} gauge")
            for key, val in sorted(data.items()):
                labels = self._format_labels(name, key)
                lines.append(f"{name}{labels} {val}")

        for name, data in self._histograms.items():
            lines.append(f"# TYPE {name} histogram")
            for key, values in sorted(data.items()):
                labels = self._format_labels(name, key)
                total = len(values)
                s = sum(values)
                lines.append(f"{name}_count{labels} {total}")
                lines.append(f"{name}_sum{labels} {s}")

        return "\n".join(lines) + "\n"

    def _format_labels(self, name: str, key: Tuple) -> str:
        names = self._label_names.get(name, [])
        if not names:
            return ""
        parts = [f'{n}="{v}"' for n, v in zip(names, key)]
        return "{" + ",".join(parts) + "}"

    def reset_counter(self, name: str) -> None:
        with self._lock:
            self._counters[name].clear()


# ──────────────────────────────
#  Trace Span (Deterministic)
# ──────────────────────────────


@dataclass(frozen=True)
class TraceSpan:
    span_id: str
    trace_id: str
    parent_id: Optional[str]
    operation: str
    start_time: float
    end_time: Optional[float] = None
    status: str = "OK"  # OK | ERROR
    attributes: Dict[str, Any] = field(default_factory=dict)


class Tracer:
    """Deterministic distributed tracing — lightweight, no OTel dependency.

    Spans are immutable after creation. Trace ID derived from correlation_id.
    """

    def __init__(self, service_name: str) -> None:
        self.service_name = service_name
        self._spans: List[TraceSpan] = []
        self._lock = threading.Lock()

    def start_span(
        self,
        trace_id: str,
        operation: str,
        parent_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> TraceSpan:
        span = TraceSpan(
            span_id=self._derive_id(f"{trace_id}:{operation}"),
            trace_id=trace_id,
            parent_id=parent_id,
            operation=operation,
            start_time=time.time(),
            attributes=attributes or {},
        )
        with self._lock:
            self._spans.append(span)
        return span

    def end_span(self, span: TraceSpan, status: str = "OK") -> TraceSpan:
        ended = TraceSpan(
            span_id=span.span_id,
            trace_id=span.trace_id,
            parent_id=span.parent_id,
            operation=span.operation,
            start_time=span.start_time,
            end_time=time.time(),
            status=status,
            attributes=span.attributes,
        )
        with self._lock:
            for i, s in enumerate(self._spans):
                if s.span_id == span.span_id:
                    self._spans[i] = ended
                    break
        return ended

    def get_trace(self, trace_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    "span_id": s.span_id,
                    "parent_id": s.parent_id,
                    "operation": s.operation,
                    "duration_ms": round((s.end_time or s.start_time) - s.start_time, 6) * 1000,
                    "status": s.status,
                    "attributes": s.attributes,
                }
                for s in self._spans
                if s.trace_id == trace_id
            ]

    def _derive_id(self, seed: str) -> str:
        import hashlib

        return hashlib.sha256(seed.encode()).hexdigest()[:16]


# ──────────────────────────────
#  Telemetry Manager
# ──────────────────────────────


class TelemetryManager:
    """Unified telemetry facade for production requests."""

    def __init__(self, component: str) -> None:
        self.logger = StructuredLogger(component)
        self.metrics = MetricsRegistry()
        self.tracer = Tracer(component)

    @contextmanager
    def request_scope(self, correlation_id: str, operation: str) -> Generator[None, None, None]:
        self.logger.set_correlation(correlation_id)
        span = self.tracer.start_span(correlation_id, operation)
        self.logger.info("request_start", operation=operation)
        try:
            yield
            self.tracer.end_span(span, status="OK")
            self.logger.info("request_end", operation=operation, status="OK")
        except Exception as exc:
            self.tracer.end_span(span, status="ERROR")
            self.logger.error("request_error", operation=operation, error_type=type(exc).__name__)
            raise
